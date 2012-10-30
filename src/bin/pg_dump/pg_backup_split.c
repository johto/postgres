/*-------------------------------------------------------------------------
 *
 * pg_backup_split.c
 *
 *  A split format dump is a directory, which contains all database objects
 *  separated into .sql files, and an "index.sql" file with psql statements
 *  to allow restoring the separated objects.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"
#include "libpq-fe.h"
#include "libpq/libpq-fs.h"
#include "pg_backup_archiver.h"
#include "dumpmem.h"
#include "dumputils.h"

#include <dirent.h>
#include <sys/stat.h>


/* XXX ugly hack: used by pg_dump.c */
int incremental_split = 0;

typedef struct
{
	char	   *filename;		/* filename excluding the directory (basename) */
	DumpId		dumpId;			/* dump id of the TocEntry */
} lclTocEntry;

typedef struct
{
	/*
	 * Our archive location. This is basically what the user specified as his
	 * backup file but of course here it is a directory.
	 */
	char	   *directory;

	FILE	   *dataFH;			/* currently open data file */

	lclTocEntry **sortedToc;	/* array of toc entires sorted by (filename, dumpId) */
} lclContext;

/* translator: this is a module name */
static const char *modulename = gettext_noop("split archiver");


/* prototypes for private functions */
static void _ArchiveEntry(ArchiveHandle *AH, TocEntry *te);
static void _StartData(ArchiveHandle *AH, TocEntry *te);
static void _EndData(ArchiveHandle *AH, TocEntry *te);
static size_t _WriteData(ArchiveHandle *AH, const void *data, size_t dLen);
static size_t _WriteBuf(ArchiveHandle *AH, const void *buf, size_t len);
static void _CloseArchive(ArchiveHandle *AH);

static void _StartBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);
static size_t _WriteBlobData(ArchiveHandle *AH, const void *data, size_t dLen);
static void _EndBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);

static size_t _splitOut(ArchiveHandle *AH, const void *buf, size_t len);

static int lclTocEntryCmp(const void *av, const void *bv);
static bool should_add_index_entry(ArchiveHandle *AH, TocEntry *te);
static void create_sorted_toc(ArchiveHandle *AH);
static void get_object_description(ArchiveHandle *AH, TocEntry *te, PQExpBuffer buf);
static void add_ownership_information(ArchiveHandle *AH, TocEntry *te);
static void set_search_path(ArchiveHandle *AH, TocEntry *te);
static void write_split_directory(ArchiveHandle *AH);

static void create_schema_directory(ArchiveHandle *AH, const char *tag);
static void create_directory(ArchiveHandle *AH, const char *fmt, ...)
	__attribute__((format(PG_PRINTF_ATTRIBUTE, 2, 3)));
static char *prepend_directory(ArchiveHandle *AH, const char *relativeFilename);
static char *encode_filename(const char *input);
static TocEntry *find_dependency(ArchiveHandle *AH, TocEntry *te);
static char *get_object_filename(ArchiveHandle *AH, TocEntry *t);


/*
 *	Init routine required by ALL formats. This is a global routine
 *	and should be declared in pg_backup_archiver.h
 *
 *	Its task is to create any extra archive context (using AH->formatData),
 *	and to initialize the supported function pointers.
 *
 *	It should also prepare whatever its input source is for reading/writing,
 *	and in the case of a read mode connection, it should load the Header & TOC.
 */
void
InitArchiveFmt_Split(ArchiveHandle *AH)
{
	lclContext *ctx;

	/* Assuming static functions, this can be copied for each format. */
	AH->ArchiveEntryPtr = _ArchiveEntry;
	AH->StartDataPtr = _StartData;
	AH->WriteDataPtr = _WriteData;
	AH->EndDataPtr = _EndData;
	AH->WriteBytePtr = NULL;
	AH->ReadBytePtr = NULL;
	AH->WriteBufPtr = _WriteBuf;
	AH->ReadBufPtr = NULL;
	AH->ClosePtr = _CloseArchive;
	AH->ReopenPtr = NULL;
	AH->PrintTocDataPtr = NULL;
	AH->ReadExtraTocPtr = NULL;
	AH->WriteExtraTocPtr = NULL;
	AH->PrintExtraTocPtr = NULL;

	AH->StartBlobsPtr = NULL;
	AH->StartBlobPtr = _StartBlob;
	AH->EndBlobPtr = _EndBlob;
	AH->EndBlobsPtr = NULL;

	AH->ClonePtr = NULL;
	AH->DeClonePtr = NULL;

	AH->CustomOutPtr = _splitOut;

	/* Set up our private context */
	ctx = (lclContext *) pg_malloc0(sizeof(lclContext));
	AH->formatData = (void *) ctx;

	ctx->dataFH = NULL;
	ctx->sortedToc = NULL;

	/* Initialize LO buffering */
	AH->lo_buf_size = LOBBUFSIZE;
	AH->lo_buf = (void *) pg_malloc(LOBBUFSIZE);

	if (!AH->fSpec || strcmp(AH->fSpec, "") == 0)
		exit_horribly(modulename, "no output directory specified\n");

	if (AH->compression != 0)
		exit_horribly(modulename, "split archive format does not support compression\n");

	if (AH->mode != archModeWrite)
        exit_horribly(modulename, "reading a split archive not supported; restore using psql\n");

	ctx->directory = AH->fSpec;

	if (!incremental_split)
	{
		if (mkdir(ctx->directory, 0700) < 0)
			exit_horribly(modulename, "could not create directory \"%s\": %s\n",
						  ctx->directory, strerror(errno));

		create_directory(AH, "EXTENSIONS");
		create_directory(AH, "BLOBS");
	}
	else
	{
		struct stat sb;
		if (stat(ctx->directory, &sb) != 0)
			exit_horribly(modulename, "\"%s\" does not exist\n", ctx->directory);
		if (!S_ISDIR(sb.st_mode))
			exit_horribly(modulename, "\"%s\" is not a directory\n", ctx->directory);
	}
}

/*
 * Custom output function to write output from ahprintf() to ctx->dataFH.
 */
static size_t
_splitOut(ArchiveHandle *AH, const void *buf, size_t len)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	if (!ctx->dataFH)
		exit_horribly(modulename, "ctx->dataFH is NULL\n");

	return fwrite(buf, 1, len, ctx->dataFH);
}

static void
create_schema_directory(ArchiveHandle *AH, const char *tag)
{
	char *namespace = encode_filename(tag);

	create_directory(AH, "%s", namespace);
	create_directory(AH, "%s/AGGREGATES", namespace);
	create_directory(AH, "%s/CHECK_CONSTRAINTS", namespace);
	create_directory(AH, "%s/CONSTRAINTS", namespace);
	create_directory(AH, "%s/FK_CONSTRAINTS", namespace);
	create_directory(AH, "%s/FUNCTIONS", namespace);
	create_directory(AH, "%s/INDEXES", namespace);
	create_directory(AH, "%s/OPERATOR_CLASSES", namespace);
	create_directory(AH, "%s/OPERATOR_FAMILIES", namespace);
	create_directory(AH, "%s/RULES", namespace);
	create_directory(AH, "%s/SEQUENCES", namespace);
	create_directory(AH, "%s/SERVERS", namespace);
	create_directory(AH, "%s/TABLEDATA", namespace);
	create_directory(AH, "%s/TABLES", namespace);
	create_directory(AH, "%s/TYPES", namespace);
	create_directory(AH, "%s/TRIGGERS", namespace);
	create_directory(AH, "%s/VIEWS", namespace);
}

/*
 * Called by the Archiver when the dumper creates a new TOC entry.
 *
 * We determine the filename for this entry.
*/
static void
_ArchiveEntry(ArchiveHandle *AH, TocEntry *te)
{
	lclTocEntry *tctx;

	tctx = (lclTocEntry *) pg_malloc0(sizeof(lclTocEntry));
	tctx->dumpId = te->dumpId;
	te->formatData = (void *) tctx;

	tctx->filename = get_object_filename(AH, te);
}


/*
 * Called by the archiver when saving TABLE DATA (not schema). This routine
 * should save whatever format-specific information is needed to read
 * the archive back.
 *
 * It is called just prior to the dumper's 'DataDumper' routine being called.
 *
 * We create the data file for writing and add any information necessary
 * for restoring the table data.
 */
static void
_StartData(ArchiveHandle *AH, TocEntry *te)
{
	lclTocEntry *tctx = (lclTocEntry *) te->formatData;
	lclContext *ctx = (lclContext *) AH->formatData;
	char	   *fname;

	fname = prepend_directory(AH, tctx->filename);

	ctx->dataFH = fopen(fname, PG_BINARY_W);
	if (ctx->dataFH == NULL)
		exit_horribly(modulename, "could not open output file \"%s\": %s\n",
					  fname, strerror(errno));

	/* set the search path */
	set_search_path(AH, te);

	/*
	 * If there's a COPY statement, add it to the beginning of the file.  If there
	 * isn't one, this must be a --inserts dump and we don't need to add anything.
	 */
	if (te->copyStmt)
		ahprintf(AH, "%s", te->copyStmt);
}

/*
 * Called by archiver when dumper calls WriteData. Note that while the
 * WriteData routine is generally called for both BLOB and TABLE data, we
 * substitute our own _WriteBlob function when dealing with BLOBs.
 *
 * We write the data to the open data file.
 */
static size_t
_WriteData(ArchiveHandle *AH, const void *data, size_t dLen)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	if (dLen == 0)
		return 0;

	return fwrite(data, 1, dLen, ctx->dataFH);
}

/*
 * Called by the archiver when a dumper's 'DataDumper' routine has
 * finished.
 *
 * We close the data file.
 */
static void
_EndData(ArchiveHandle *AH, TocEntry *te)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	/* Close the file */
	fclose(ctx->dataFH);

	ctx->dataFH = NULL;
}

/*
 * Write a buffer of data to the archive.
 * Called by the archiver to write a block of bytes to a data file.
 */
static size_t
_WriteBuf(ArchiveHandle *AH, const void *buf, size_t len)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	size_t		res;

	res = fwrite(buf, 1, len, ctx->dataFH);
	if (res != len)
		exit_horribly(modulename, "could not write to output file: %s\n",
					  strerror(errno));

	return res;
}

/*
 * Close the archive.
 *
 * When writing the archive, this is the routine that actually starts
 * the process of saving it to files. No data should be written prior
 * to this point, since the user could sort the TOC after creating it.
 *
 * Usually when an archive is written, we should call WriteHead() and
 * WriteToc().  But since we don't write a TOC file at all, we can just
 * skip that and write the index file from the TocEntry array.  We do,
 * however, use WriteDataChunks() to write the table data.
 */
static void
_CloseArchive(ArchiveHandle *AH)
{
	if (AH->mode == archModeWrite)
	{
		WriteDataChunks(AH);
		write_split_directory(AH);
	}
}


/*
 * BLOB support
 */

/*
 * Called by the archiver when we're about to start dumping a blob.
 *
 * We create a file to write the blob to.
 */
static void
_StartBlob(ArchiveHandle *AH, TocEntry *te, Oid oid)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	char		fname[MAXPGPATH];

	snprintf(fname, MAXPGPATH, "%s/BLOBS/%u.sql", ctx->directory, oid);
	ctx->dataFH = fopen(fname, PG_BINARY_W);
	if (ctx->dataFH == NULL)
		exit_horribly(modulename, "could not open output file \"%s\": %s\n",
					  fname, strerror(errno));

	ahprintf(AH, "SELECT pg_catalog.lo_open('%u', %d);\n", oid, INV_WRITE);

	/* Substitute a different function to deal with BLOB data */
	AH->WriteDataPtr = _WriteBlobData;
}

/*
 * Called by dumper via archiver from within a data dump routine.
 * We substitute this for _WriteData while emitting a BLOB.
 */
static size_t
_WriteBlobData(ArchiveHandle *AH, const void *data, size_t dLen)
{
	if (dLen > 0)
	{
		PQExpBuffer buf = createPQExpBuffer();
		appendByteaLiteralAHX(buf,
							  (const unsigned char *) data,
							  dLen,
							  AH);
		
		ahprintf(AH, "SELECT pg_catalog.lowrite(0, %s);\n", buf->data);
		destroyPQExpBuffer(buf);
	}

	return dLen;
}

/*
 * Called by the archiver when the dumper is finished writing a blob.
 *
 * We close the blob file and write an entry to the blob TOC file for it.
 */
static void
_EndBlob(ArchiveHandle *AH, TocEntry *te, Oid oid)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	ahprintf(AH, "SELECT pg_catalog.lo_close(0);\n\n");

	/* Close the BLOB data file itself */
	fclose(ctx->dataFH);
	ctx->dataFH = NULL;

	/* Restore the pointer we substituted in _StartBlob() */
	AH->WriteDataPtr = _WriteData;
}


static int
lclTocEntryCmp(const void *av, const void *bv)
{
	int c;
	lclTocEntry *a = *((lclTocEntry **) av);
	lclTocEntry *b = *((lclTocEntry **) bv);

	/* NULLs should sort last */
	c = (b->filename != NULL) - (a->filename != NULL);
	if (c != 0)
		return c;

	/* don't call strcmp() on NULLs */
	if (a->filename != NULL && b->filename != NULL)
	{
		c = strcmp(a->filename, b->filename);
		if (c != 0)
			return c;
	}

	return a->dumpId - b->dumpId;
}

static bool
should_add_index_entry(ArchiveHandle *AH, TocEntry *te)
{
	lclTocEntry **sortedToc;
	lclTocEntry **pte;
	lclTocEntry **key;
	lclTocEntry *prevte;

	key = (lclTocEntry **) &te->formatData;

	sortedToc = ((lclContext *) AH->formatData)->sortedToc;
	if (!sortedToc)
		exit_horribly(modulename, "formatData->sortedToc is NULL\n");
		
	pte = (lclTocEntry **) bsearch(key, sortedToc,
								   AH->tocCount, sizeof(lclTocEntry *), lclTocEntryCmp);

	if (!pte)
		exit_horribly(modulename, "binary search failed\n");

	/* If there's no previous entry, always add an index entry */
	if (pte == sortedToc)
		return true;

	/*
	 * If there's a previous entry with the same filename, we don't want to add
	 * an index entry for this TocEntry.  Note that NULLs sort last so the
	 * previous entry's filename can never be NULL.
	 */
	prevte = *(pte - 1);
	return strcmp(prevte->filename, (*key)->filename) != 0;
}

/*
 * Create a list of lclTocEntries sorted by (filename, dumpId).  This list is
 * used when creating the index file to make sure we don't include a file
 * multiple times.
 */
static void
create_sorted_toc(ArchiveHandle *AH)
{
	int i;
	lclContext *ctx;
	TocEntry *te;

	ctx = (lclContext *) AH->formatData;
	/* sanity checks */
	if (!ctx)
		exit_horribly(modulename, "formatData not allocated\n");
	if (ctx->sortedToc != NULL)
		exit_horribly(modulename, "formatData->sortedToc not NULL\n");

	ctx->sortedToc = (lclTocEntry **) pg_malloc0(sizeof(lclTocEntry *) * AH->tocCount);
	for (i = 0, te = AH->toc->next; te != AH->toc; i++, te = te->next)
		ctx->sortedToc[i] = (lclTocEntry *) te->formatData;

	qsort(ctx->sortedToc, AH->tocCount, sizeof(lclTocEntry *), lclTocEntryCmp);
}

static void
get_object_description(ArchiveHandle *AH, TocEntry *te, PQExpBuffer buf)
{
	const char *type = te->desc;

	/* use ALTER TABLE for views and sequences */
	if (strcmp(type, "VIEW") == 0 || strcmp(type, "SEQUENCE") == 0)
		type = "TABLE";

	/* must not call fmtId() on BLOBs */
	if (strcmp(type, "BLOB") == 0)
	{
		appendPQExpBuffer(buf, "LARGE OBJECT %s ", te->tag);
		return;
	}

	/* a number of objects that require no special treatment */
	if (strcmp(type, "COLLATION") == 0 ||
		strcmp(type, "CONVERSION") == 0 ||
		strcmp(type, "DOMAIN") == 0 ||
		strcmp(type, "DATABASE") == 0 ||
		strcmp(type, "FOREIGN DATA WRAPPER") == 0 ||
		strcmp(type, "FOREIGN TABLE") == 0 ||
		strcmp(type, "INDEX") == 0 ||
		strcmp(type, "LARGE OBJECT") == 0 ||
		strcmp(type, "TABLE") == 0 ||
		strcmp(type, "TEXT SEARCH CONFIGURATION") == 0 ||
		strcmp(type, "TEXT SEARCH DICTIONARY") == 0 ||
		strcmp(type, "TYPE") == 0 ||
		strcmp(type, "PROCEDURAL LANGUAGE") == 0 ||
		strcmp(type, "SCHEMA") == 0 ||
		strcmp(type, "SERVER") == 0 ||
		strcmp(type, "USER MAPPING") == 0)
	{
		appendPQExpBuffer(buf, "%s ", type);
		if (te->namespace)
			appendPQExpBuffer(buf, "%s.", fmtId(te->namespace));
		appendPQExpBuffer(buf, "%s ", fmtId(te->tag));

		return;
	}

	 /*
	  * These object types require additional decoration.  Fortunately, the
	  * information needed is exactly what's in the DROP command.
	  */
	if (strcmp(type, "AGGREGATE") == 0 ||
		strcmp(type, "FUNCTION") == 0 ||
		strcmp(type, "OPERATOR") == 0 ||
		strcmp(type, "OPERATOR CLASS") == 0 ||
		strcmp(type, "OPERATOR FAMILY") == 0)
	{
		/* chop "DROP " off the front and make a modifyable copy */
		char *first = pg_strdup(te->dropStmt + 5);
		char *last;

		/* strip off any ';' or '\n' at the end */
		last = first + strlen(first) - 1;
		while (last >= first && (*last == '\n' || *last == ';'))
			last--;
		*(last + 1) = '\0';		

		appendPQExpBuffer(buf, "%s ", first);

		free(first);

		return;
	}

	exit_horribly(modulename, "don't know how to set owner for object type %s\n", type);
}

static void
add_ownership_information(ArchiveHandle *AH, TocEntry *te)
{
	PQExpBuffer temp;

	/* skip objects that don't have an owner */
	if (strcmp(te->desc, "ACL") == 0 ||
		strcmp(te->desc, "CAST") == 0 ||
		strcmp(te->desc, "COMMENT") == 0 ||
		strcmp(te->desc, "CHECK CONSTRAINT") == 0 ||
		strcmp(te->desc, "CONSTRAINT") == 0 ||
		strcmp(te->desc, "DEFAULT") == 0 ||
		strcmp(te->desc, "ENCODING") == 0 ||
		strcmp(te->desc, "EXTENSION") == 0 ||
		strcmp(te->desc, "FK CONSTRAINT") == 0 ||
		strcmp(te->desc, "LARGE OBJECT") == 0 ||
		strcmp(te->desc, "RULE") == 0 ||
		strcmp(te->desc, "SEQUENCE OWNED BY") == 0 ||
		strcmp(te->desc, "SEQUENCE SET") == 0 ||
		strcmp(te->desc, "STDSTRINGS") == 0 ||
		strcmp(te->desc, "TRIGGER") == 0)
		return;

	temp = createPQExpBuffer();
	appendPQExpBuffer(temp, "ALTER ");
	get_object_description(AH, te, temp);
	appendPQExpBuffer(temp, "OWNER TO %s;", fmtId(te->owner));
	ahprintf(AH, "%s\n\n", temp->data);
	destroyPQExpBuffer(temp);
}

static void
set_search_path(ArchiveHandle *AH, TocEntry *te)
{
	if (!te->namespace)
		return;

	/*
	 * We want to add the namespace to information to each object regardless
	 * of the previous object's namespace; that way it is easy to see when an
	 * object is moved to another schema.
	 */
	if (strcmp(te->namespace, "pg_catalog") == 0)
		ahprintf(AH, "SET search_path TO pg_catalog;\n\n");
	else
		ahprintf(AH, "SET search_path TO '%s', pg_catalog;\n\n", te->namespace);
}

/*
 * Majority of the work is done here.  We scan through the list of TOC entries
 * and write the object definitions into their respective files.  At the same
 * time, we build the "index" file.
 */
static void
write_split_directory(ArchiveHandle *AH)
{
	lclContext *ctx;
	TocEntry *te;
	FILE *indexFH;
	char buf[512];

	ctx = (lclContext *) AH->formatData;

	create_sorted_toc(AH);

	indexFH = fopen(prepend_directory(AH, "index.sql"), "w");
	if (!indexFH)
		exit_horribly(modulename, "could not open index.sql: %s\n", strerror(errno));

	snprintf(buf, sizeof(buf),	"\n-- PostgreSQL split database dump\n\n"
								"SET client_min_messages TO 'warning';\n"
								"SET client_encoding TO '%s';\n"
								"SET check_function_bodies TO false;\n\n",
									pg_encoding_to_char(AH->public.encoding));
	if (fwrite(buf, 1, strlen(buf), indexFH) != strlen(buf))
		exit_horribly(modulename, "could not write to index file: %s\n", strerror(errno));

	for (te = AH->toc->next; te != AH->toc; te = te->next)
	{
		lclTocEntry *tctx;
		const char *filename;
		bool add_entry;

		tctx = (lclTocEntry *) te->formatData;

		/* for TABLEDATA, the only thing we need to do is add an index entry */
		if (strcmp(te->desc, "TABLE DATA") == 0)
		{
			snprintf(buf, sizeof(buf), "\\i %s\n", tctx->filename);
			if (fwrite(buf, 1, strlen(buf), indexFH) != strlen(buf))
				exit_horribly(modulename, "could not write index file: %s\n", strerror(errno));
			continue;
		}

		/* skip data */
		if (te->dataDumper)
			continue;

		/*  if there's no filename we need to skip this entry, see _ArchiveEntry() */
		if (!tctx->filename)
			continue;

		/* add an index entry if necessary */
		add_entry = should_add_index_entry(AH, te);
		if (add_entry)
		{
			snprintf(buf, sizeof(buf), "\\i %s\n", tctx->filename);
			if (fwrite(buf, 1, strlen(buf), indexFH) != strlen(buf))
				exit_horribly(modulename, "could not write index file: %s\n", strerror(errno));
		}

		/*
		 * In incremental split dump mode, we don't want to dump the view definitions
		 * in any case.  But we do still want the index entries, so this is the place
		 * to stop processing views.
		 *
		 * Any object depending on a view is handled in get_object_filename, so we
		 * don't have to worry about that here.
		 */
		if (incremental_split && strcmp(te->desc, "VIEW") == 0)
			continue;

		/* 
		 * Special case: don't try to re-create the "public" schema.  Note that we
		 * still need to create the index entry because all schemas use the same
		 * "schemaless.sql" file, so make sure that happens before we reach this
		 * point.
		 */
		if (strcmp(te->desc, "SCHEMA") == 0 &&
			strcmp(te->tag, "public") == 0)
			continue;

		filename = prepend_directory(AH, tctx->filename);

		/*
		 * Multiple objects can map to the same file, so open in "append" mode after
		 * the first such object has been processed.
		 */
		if (add_entry)
			ctx->dataFH = fopen(filename, "w");
		else
			ctx->dataFH = fopen(filename, "a");
		if (!ctx->dataFH)
			exit_horribly(modulename, "could not open file \"%s\": %s\n",
							filename, strerror(errno));

		set_search_path(AH, te);

		ahprintf(AH, "%s\n", te->defn);
		
		/*
		 * Special case: add \i for BLOBs into the "blobs.sql" data file.  It's ugly
		 * to have this here, but there really isn't any better place.
		 */
		if (strcmp(te->desc, "BLOB") == 0)
			ahprintf(AH, "\\i BLOBS/%s.sql\n\n", te->tag);

		add_ownership_information(AH, te);

		fclose(ctx->dataFH);
		ctx->dataFH = NULL;
	}

	fclose(indexFH);
}


static void
create_directory(ArchiveHandle *AH, const char *fmt, ...)
{
	va_list ap;
	char reldir[MAXPGPATH];
	char *directory;

	va_start(ap, fmt);
	vsnprintf(reldir, MAXPGPATH, fmt, ap);
	va_end(ap);

	directory = prepend_directory(AH, reldir);
	if (mkdir(directory, 0700) < 0)
		exit_horribly(modulename, "could not create directory \"%s\": %s\n",
					  directory, strerror(errno));
}


static char *
prepend_directory(ArchiveHandle *AH, const char *relativeFilename)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	static char buf[MAXPGPATH];
	char	   *dname;

	dname = ctx->directory;

	if (strlen(dname) + 1 + strlen(relativeFilename) + 1 > MAXPGPATH)
		exit_horribly(modulename, "file name too long: \"%s\"\n", dname);

	strcpy(buf, dname);
	strcat(buf, "/");
	strcat(buf, relativeFilename);

	return buf;
}


/*
 * Encode a filename to fit in the "Portable Filename Character Set" in POSIX.
 *
 * Any character not part of that set will be replaced with '_'.  Also, because
 * some file system are case insensitive, we need to lower-case all file names.
 *
 * Because we don't know what encoding the data is in, if we see multiple
 * consecutive octets outside the set, we only output one underscore
 * representing all of them.  That way one can easily compare the outputs of
 * dumps taken on systems with different encoding.
 */
static char *
encode_filename(const char *input)
{
	static char buf[MAXPGPATH];
	const char *p = input;
	char *op = buf;
	bool replaced_previous;

	/*
	 * The input filename should be at most 64 bytes (because it comes from the
	 * "name" datatype), so this should never happen.
	 */
	if (strlen(input) >= MAXPGPATH)
		exit_horribly(modulename, "file name too long: \"%s\"\n", input);

	for (replaced_previous = false;;)
	{
		if (*p == 0)
			break;

		if (*p >= 'A' && *p <= 'Z')
		{
			*op++ = tolower(*p);
			replaced_previous = false;
		}
		else if ((*p >= 'a' && *p <= 'z') ||
				 (*p >= '0' && *p <= '9') ||
				 *p == '.' || *p == '_' || *p == '-')
		{
			*op++ = *p;
			replaced_previous = false;
		}
		else if (!replaced_previous)
		{
			*op++ = '_';
			replaced_previous = true;
		}

		p++;
	}

	*op = '\0';

	return buf;
}

/*
 * Given a pointer to the start of an identifier, returns a pointer to one
 * character past that identifier, or NULL if no valid identifier was found.
 * Also we don't remove any escaped quotes inside quoted identifiers, so the
 * caller should be prepared to deal with that.  In the (currently) only use of
 * this function it won't matter, since double quotes will be replaced with a
 * single underscore when encoding the filename.
 */
static char *
skip_identifier(char *buf)
{
	char *p = buf;
	bool quoted = false;

	if (*p == '"')
		quoted = true;
	/* without quotes, the first character needs special treatment */
	else if (!((*p >= 'a' && *p <= 'z') || *p == '_'))
		return NULL;
	p++;

	for (;;)
	{
		/*
		 * If we're parsing a quoted identifier, stop at a quote unless it's escaped.
		 * Also make sure we don't go past the end of the string.
		 *
		 * Or if we're not parsing a quoted identifier, stop whenever we encounter
		 * any character which would require quotes.  Note that we don't care what
		 * the character is; it's up to the caller to see whether it makes sense to
		 * have that character in there.
		 */
		if (quoted)
		{
			if (*p == '"')
			{
				p++;
				if (*p != '"')
					return p;
			}
			else if (*p == '\0')
				return NULL;
		}
		else if (!((*p >= 'a' && *p <= 'z') ||
				  (*p >= '0' && *p <= '9') ||
				  (*p == '_')))
			return p;

		p++;
	}
}

static TocEntry *
find_dependency(ArchiveHandle *AH, TocEntry *te)
{
	DumpId depId;
	TocEntry *depte;

	if (te->nDeps != 1)
		exit_horribly(modulename, "unexpected number of dependencies (%d) for \"%s\" %d\n", te->nDeps, te->desc, te->dumpId);

	depId = te->dependencies[0];

	for (depte = te->prev; depte != te; depte = depte->prev)
	{
		if (depte->dumpId == depId)
			return depte;
	}

	exit_horribly(modulename, "could not find dependency %d for \"%s\" %d\n", depId, te->desc, te->dumpId);
}

static char *
get_object_filename(ArchiveHandle *AH, TocEntry *te)
{
	int i;
	char path[MAXPGPATH];

	/*
	 * List of object types we can simply dump into  [schema/]OBJTYPE/tag.sql.
	 * The first argument is the object type (te->desc) and the second one is
	 * the subdirectory to dump to.
	 */
	const char * const object_types[][2] =
	{
		{ "AGGREGATE",			"AGGREGATES"		},
		{ "CHECK CONSTRAINT",	"CHECK_CONSTRAINTS" },
		{ "CONSTRAINT",			"CONSTRAINTS"		},
		{ "EXTENSION",			"EXTENSIONS"		},
		{ "FK CONSTRAINT",		"FK_CONSTRAINTS"	},
		{ "INDEX",				"INDEXES"			},
		{ "SEQUENCE",			"SEQUENCES"			},
		{ "OPERATOR CLASS",		"OPERATOR_CLASSES"	},
		{ "OPERATOR FAMILY",	"OPERATOR_FAMILIES"	},
		{ "RULE",				"RULES"				},
		{ "SERVER",				"SERVERS"			},
		{ "TABLE",				"TABLES"			},
		{ "TYPE",				"TYPES"				},
		{ "TRIGGER",			"TRIGGERS"			},
		{ "VIEW",				"VIEWS"				}
	};


	if (te->dataDumper)
	{
		if (strcmp(te->desc, "TABLE DATA") == 0)
		{
			snprintf(path, MAXPGPATH, "%s/TABLEDATA/%d.sql", encode_filename(te->namespace), te->dumpId);
			return pg_strdup(path);
		}
		else if (strcmp(te->desc, "BLOBS") == 0)
		{
			/*
			 * Return NULL for BLOBS.  The _*_Blob functions will know how to find the
			 * correct files -- we don't since we don't know the oids yet.
			 */
			return NULL;
		}

		exit_horribly(modulename, "unknown data object %s\n", te->desc);
	}

	/*
	 * There's no need to create a database; one should always exist when
	 * restoring.
	 */
	if (strcmp(te->desc, "DATABASE") == 0)
		return NULL;

	if (strcmp(te->desc, "BLOB") == 0)
	{
		snprintf(path, MAXPGPATH, "blobs.sql");
		return pg_strdup(path);
	}

	/* for schemas, create the directory before dumping the definition */
	if (strcmp(te->desc, "SCHEMA") == 0 && !incremental_split)
		create_schema_directory(AH, te->tag);

	/* schemaless objects which don't depend on anything */
	if (strcmp(te->desc, "COLLATION") == 0 ||
		strcmp(te->desc, "ENCODING") == 0 ||
		strcmp(te->desc, "PROCEDURAL LANGUAGE") == 0 ||
		strcmp(te->desc, "SCHEMA") == 0 ||
		strcmp(te->desc, "STDSTRINGS") == 0)
		return pg_strdup("schemaless.sql");

	/*
	 * These objects depend on other objects so they can't be put into
	 * schemaless.sql.
	 */
	if (strcmp(te->desc, "CAST") == 0)
		return pg_strdup("casts.sql");
	if (strcmp(te->desc, "CONVERSION") == 0)
		return pg_strdup("conversions.sql");
	if (strcmp(te->desc, "DEFAULT") == 0)
		return pg_strdup("defaults.sql");
	if (strcmp(te->desc, "USER MAPPING") == 0)
		return pg_strdup("user_mappings.sql");
	if (strcmp(te->desc, "OPERATOR") == 0)
	{
		snprintf(path, MAXPGPATH, "%s/operators.sql", encode_filename(te->namespace));
		return pg_strdup(path);
	}

	/*
	 * These objects should always contain dependency information.  Find the
	 * object we depend  te  depends on, and dump them to the same file.
	 */
	if (strcmp(te->desc, "ACL") == 0 ||
		strcmp(te->desc, "SEQUENCE SET") == 0 ||
		strcmp(te->desc, "SEQUENCE OWNED BY") == 0 ||
		strcmp(te->desc, "COMMENT") == 0)
	{
		TocEntry *depte;
		lclTocEntry *depctx;

		depte = find_dependency(AH, te);
		depctx = (lclTocEntry *) depte->formatData;
		if (!depctx)
			exit_horribly(modulename, "unexpected NULL formatData\n");
		
		/* in incremental split dump mode, don't dump anything that depends on a view */
		if (incremental_split && strcmp(depte->desc, "VIEW") == 0)
			return NULL;

		/* no need to strdup() */
		return depctx->filename;
	}

	if (strcmp(te->desc, "AGGREGATE") == 0 ||
		strcmp(te->desc, "FUNCTION") == 0)
	{
		char *buf;
		char *proname;
		char *p;
		char *fname;
		PQExpBuffer temp;

		/*
		 * Parse the actual function/aggregate name from the DROP statement.  This is
		 * easier than parsing it from the tag since the object name is never quoted
		 * inside the tag so we can't reliably tell where the argument list begins.
		 */
		if (strncmp(te->dropStmt, "DROP FUNCTION ", 14) == 0)
			buf = pg_strdup(te->dropStmt + 14);
		else if (strncmp(te->dropStmt, "DROP AGGREGATE ", 15) == 0)
			buf = pg_strdup(te->dropStmt + 15);
		else
			exit_horribly(modulename, "could not parse DROP statement \"%s\"\n", te->dropStmt);

		proname = buf;

		p = skip_identifier(proname);
		if (!p)
			exit_horribly(modulename, "could not parse DROP statement \"%s\"\n", te->dropStmt);
		
		/*
		 * If there's a namespace, ignore it and find the end of the next identifier.
		 * That should be the name of the function.
		 */
		if (*p == '.')
		{
			proname = p + 1;
			p = skip_identifier(proname);
			if (!p)
				exit_horribly(modulename, "could not parse DROP statement \"%s\"\n", te->dropStmt);
		}

		/* the argument list should be right after the function name */
		if (*p != '(')
			exit_horribly(modulename, "could not parse DROP statement \"%s\"\n", te->dropStmt);

		/*
		 * Terminate the identifier before the argument list definition, removing
		 * quotes if necessary.
		 */
		if (*proname == '"')
		{
			proname++;
			*(p-1) = '\0';
		}
		else
			*p = '\0';

		temp = createPQExpBuffer();
		/* must use 2 steps here because encode_filename() is nonreentrant */
		appendPQExpBuffer(temp, "%s/", encode_filename(te->namespace));
		appendPQExpBuffer(temp, "%sS/%s.sql", te->desc, encode_filename(proname));

		fname = pg_strdup(temp->data);

		destroyPQExpBuffer(temp);
		free(buf);

		return fname;
	}

	/* finally, see if it's any of the objects that require no special treatment */
	for (i = 0; i < sizeof(object_types) / sizeof(object_types[0]); ++i)
	{
		if (strcmp(object_types[i][0], te->desc) == 0)
		{
			const char *objsubdir = object_types[i][1];

			if (te->namespace)
			{
				/* must use 2 steps here because encode_filename() is nonreentrant */
				char *namespace = pg_strdup(encode_filename(te->namespace));
				snprintf(path, MAXPGPATH, "%s/%s/%s.sql", namespace,
						 objsubdir, encode_filename(te->tag));
				free(namespace);
			}
			else
				snprintf(path, MAXPGPATH, "%s/%s.sql",
						 objsubdir, encode_filename(te->tag));

			return pg_strdup(path);
		}
	}

	exit_horribly(modulename, "unknown object type \"%s\"\n", te->desc);
}
