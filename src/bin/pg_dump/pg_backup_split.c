/*-------------------------------------------------------------------------
 *
 * pg_backup_split.c
 *
 *	A directory format dump is a directory, which contains a "toc.dat" file
 *	for the TOC, and a separate file for each data entry, named "<oid>.dat".
 *	Large objects (BLOBs) are stored in separate files named "blob_<uid>.dat",
 *	and there's a plain-text TOC file for them called "blobs.toc". If
 *	compression is used, each data file is individually compressed and the
 *	".gz" suffix is added to the filenames. The TOC files are never
 *	compressed by pg_dump, however they are accepted with the .gz suffix too,
 *	in case the user has manually compressed them with 'gzip'.
 *
 *	NOTE: This format is identical to the files written in the tar file in
 *	the 'tar' format, except that we don't write the restore.sql file (TODO),
 *	and the tar format doesn't support compression. Please keep the formats in
 *	sync.
 *
 * XXX updateme
 *
 *-------------------------------------------------------------------------
 */

#include "compress_io.h"
#include "dumpmem.h"
#include "dumputils.h"

#include <dirent.h>
#include <sys/stat.h>

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

	cfp		   *dataFH;			/* currently open data file */

	cfp		   *blobsTocFH;		/* file handle for blobs.toc */

	lclTocEntry **sortedToc;	/* array of toc entires sorted by (filename, dumpId) */
} lclContext;

/* translator: this is a module name */
static const char *modulename = gettext_noop("split archiver");


/* prototypes for private functions */
static void _ArchiveEntry(ArchiveHandle *AH, TocEntry *te);
static void _StartData(ArchiveHandle *AH, TocEntry *te);
static void _EndData(ArchiveHandle *AH, TocEntry *te);
static size_t _WriteData(ArchiveHandle *AH, const void *data, size_t dLen);
static int	_WriteByte(ArchiveHandle *AH, const int i);
static int	_ReadByte(ArchiveHandle *);
static size_t _WriteBuf(ArchiveHandle *AH, const void *buf, size_t len);
static void _CloseArchive(ArchiveHandle *AH);

static void _StartBlobs(ArchiveHandle *AH, TocEntry *te);
static void _StartBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);
static void _EndBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);
static void _EndBlobs(ArchiveHandle *AH, TocEntry *te);

static int lclTocEntryCmp(const void *av, const void *bv);
static bool should_add_index_entry(ArchiveHandle *AH, TocEntry *te);
static void create_sorted_toc(ArchiveHandle *AH);
static void get_object_description(ArchiveHandle *AH, TocEntry *te, FILE *fh);
static void add_ownership_information(ArchiveHandle *AH, TocEntry *te, FILE *fh);
static void set_search_path(ArchiveHandle *AH, TocEntry *te, FILE *fh);
static void write_split_directory(ArchiveHandle *AH);

static void create_schema_directory(ArchiveHandle *AH, const char *tag);
static void create_directory(ArchiveHandle *AH, const char *fmt, ...)
	__attribute__((format(PG_PRINTF_ATTRIBUTE, 2, 3)));
static char *prepend_directory(ArchiveHandle *AH, const char *relativeFilename);
static char *encode_filename(const char *input);
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
	AH->WriteBytePtr = _WriteByte;
	AH->ReadBytePtr = _ReadByte;
	AH->WriteBufPtr = _WriteBuf;
	AH->ReadBufPtr = NULL;
	AH->ClosePtr = _CloseArchive;
	AH->ReopenPtr = NULL;
	AH->PrintTocDataPtr = NULL;
	AH->ReadExtraTocPtr = NULL;
	AH->WriteExtraTocPtr = NULL;
	AH->PrintExtraTocPtr = NULL;

	AH->StartBlobsPtr = _StartBlobs;
	AH->StartBlobPtr = _StartBlob;
	AH->EndBlobPtr = _EndBlob;
	AH->EndBlobsPtr = _EndBlobs;

	AH->ClonePtr = NULL;
	AH->DeClonePtr = NULL;

	/* Set up our private context */
	ctx = (lclContext *) pg_malloc0(sizeof(lclContext));
	AH->formatData = (void *) ctx;

	ctx->dataFH = NULL;
	ctx->blobsTocFH = NULL;
	ctx->sortedToc = NULL;

	/* Initialize LO buffering */
	AH->lo_buf_size = LOBBUFSIZE;
	AH->lo_buf = (void *) pg_malloc(LOBBUFSIZE);

	if (!AH->fSpec || strcmp(AH->fSpec, "") == 0)
		exit_horribly(modulename, "no output directory specified\n");

	ctx->directory = AH->fSpec;

	if (AH->mode == archModeWrite)
	{
		if (mkdir(ctx->directory, 0700) < 0)
			exit_horribly(modulename, "could not create directory \"%s\": %s\n",
						  ctx->directory, strerror(errno));

		create_directory(AH, "EXTENSIONS");
	}
	else
        exit_horribly(modulename, "reading a split archive not supported; restore using psql\n");
}

static void
create_schema_directory(ArchiveHandle *AH, const char *tag)
{
	create_directory(AH, "%s", tag);
	create_directory(AH, "%s/FUNCTIONS", tag);
	create_directory(AH, "%s/TABLES", tag);
	create_directory(AH, "%s/INDEXES", tag);
	create_directory(AH, "%s/SEQUENCES", tag);
	create_directory(AH, "%s/VIEWS", tag);
	create_directory(AH, "%s/CONSTRAINTS", tag);
	create_directory(AH, "%s/FK_CONSTRAINTS", tag);
	create_directory(AH, "%s/TYPES", tag);
	create_directory(AH, "%s/TRIGGERS", tag);
	create_directory(AH, "%s/AGGREGATES", tag);
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
	char		fn[MAXPGPATH];

	tctx = (lclTocEntry *) pg_malloc0(sizeof(lclTocEntry));
	tctx->dumpId = te->dumpId;
	te->formatData = (void *) tctx;

	if (te->dataDumper)
	{
		snprintf(fn, MAXPGPATH, "%s/TABLES/%d.dat", te->namespace, te->dumpId);
		tctx->filename = pg_strdup(fn);
		return;
	}

	tctx->filename = get_object_filename(AH, te);
}


/*
 * Called by the archiver when saving TABLE DATA (not schema). This routine
 * should save whatever format-specific information is needed to read
 * the archive back.
 *
 * It is called just prior to the dumper's 'DataDumper' routine being called.
 *
 * We create the data file for writing.
 */
static void
_StartData(ArchiveHandle *AH, TocEntry *te)
{
	lclTocEntry *tctx = (lclTocEntry *) te->formatData;
	lclContext *ctx = (lclContext *) AH->formatData;
	char	   *fname;

	fname = prepend_directory(AH, tctx->filename);

	ctx->dataFH = cfopen_write(fname, PG_BINARY_W, AH->compression);
	if (ctx->dataFH == NULL)
		exit_horribly(modulename, "could not open output file \"%s\": %s\n",
					  fname, strerror(errno));
}

/*
 * Called by archiver when dumper calls WriteData. This routine is
 * called for both BLOB and TABLE data; it is the responsibility of
 * the format to manage each kind of data using StartBlob/StartData.
 *
 * It should only be called from within a DataDumper routine.
 *
 * We write the data to the open data file.
 */
static size_t
_WriteData(ArchiveHandle *AH, const void *data, size_t dLen)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	if (dLen == 0)
		return 0;

	return cfwrite(data, dLen, ctx->dataFH);
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
	cfclose(ctx->dataFH);

	ctx->dataFH = NULL;
}

/*
 * Write a byte of data to the archive.
 * Called by the archiver to do integer & byte output to the archive.
 * These routines are only used to read & write the headers & TOC.
 */
static int
_WriteByte(ArchiveHandle *AH, const int i)
{
	unsigned char c = (unsigned char) i;
	lclContext *ctx = (lclContext *) AH->formatData;

	if (cfwrite(&c, 1, ctx->dataFH) != 1)
		exit_horribly(modulename, "could not write byte\n");

	return 1;
}

/*
 * Read a byte of data from the archive.
 * Called by the archiver to read bytes & integers from the archive.
 * These routines are only used to read & write headers & TOC.
 * EOF should be treated as a fatal error.
 */
static int
_ReadByte(ArchiveHandle *AH)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	int			res;

	res = cfgetc(ctx->dataFH);
	if (res == EOF)
		exit_horribly(modulename, "unexpected end of file\n");

	return res;
}

/*
 * Write a buffer of data to the archive.
 * Called by the archiver to write a block of bytes to the TOC or a data file.
 */
static size_t
_WriteBuf(ArchiveHandle *AH, const void *buf, size_t len)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	size_t		res;

	res = cfwrite(buf, len, ctx->dataFH);
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
 * If an archive is to be written, this routine must call:
 *		WriteHead			to save the archive header
 *		WriteToc			to save the TOC entries
 *		WriteDataChunks		to save all DATA & BLOBs.
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
 * Called by the archiver when starting to save all BLOB DATA (not schema).
 * It is called just prior to the dumper's DataDumper routine.
 *
 * We open the large object TOC file here, so that we can append a line to
 * it for each blob.
 */
static void
_StartBlobs(ArchiveHandle *AH, TocEntry *te)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	char	   *fname;

	fname = prepend_directory(AH, "blobs.toc");

	/* The blob TOC file is never compressed */
	ctx->blobsTocFH = cfopen_write(fname, "ab", 0);
	if (ctx->blobsTocFH == NULL)
		exit_horribly(modulename, "could not open output file \"%s\": %s\n",
					  fname, strerror(errno));
}

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

	snprintf(fname, MAXPGPATH, "%s/blob_%u.dat", ctx->directory, oid);

	ctx->dataFH = cfopen_write(fname, PG_BINARY_W, AH->compression);

	if (ctx->dataFH == NULL)
		exit_horribly(modulename, "could not open output file \"%s\": %s\n",
					  fname, strerror(errno));
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
	char		buf[50];
	int			len;

	/* Close the BLOB data file itself */
	cfclose(ctx->dataFH);
	ctx->dataFH = NULL;

	/* register the blob in blobs.toc */
	len = snprintf(buf, sizeof(buf), "%u blob_%u.dat\n", oid, oid);
	if (cfwrite(buf, len, ctx->blobsTocFH) != len)
		exit_horribly(modulename, "could not write to blobs TOC file\n");
}

/*
 * Called by the archiver when finishing saving all BLOB DATA.
 *
 * We close the blobs TOC file.
 */
static void
_EndBlobs(ArchiveHandle *AH, TocEntry *te)
{
	lclContext *ctx = (lclContext *) AH->formatData;

	cfclose(ctx->blobsTocFH);
	ctx->blobsTocFH = NULL;
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

	c = strcmp(a->filename, b->filename);
	if (c != 0)
		return c;

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
get_object_description(ArchiveHandle *AH, TocEntry *te, FILE *fh)
{
	const char *type = te->desc;

	/* Use ALTER TABLE for views and sequences */
	if (strcmp(type, "VIEW") == 0 || strcmp(type, "SEQUENCE") == 0)
		type = "TABLE";

	/* LARGE OBJECT for BLOBs */
	if (strcmp(type, "BLOB") == 0)
		type = "LARGE OBJECT";


	if (strcmp(type, "COLLATION") == 0 ||
		strcmp(type, "CONVERSION") == 0 ||
		strcmp(type, "DOMAIN") == 0 ||
		strcmp(type, "DATABASE") == 0 ||
		strcmp(type, "FOREIGN DATA WRAPPER") == 0 ||
		strcmp(type, "FOREIGN TABLE") == 0 ||
		strcmp(type, "INDEX") == 0 ||
		strcmp(type, "TABLE") == 0 ||
		strcmp(type, "TEXT SEARCH CONFIGURATION") == 0 ||
		strcmp(type, "TEXT SEARCH DICTIONARY") == 0 ||
		strcmp(type, "TYPE") == 0 ||
		strcmp(type, "PROCEDURAL LANGUAGE") == 0 ||
		strcmp(type, "SCHEMA") == 0 ||
		strcmp(type, "SERVER") == 0 ||
		strcmp(type, "USER MAPPING") == 0)
	{
		fprintf(fh, "%s ", type);
		if (te->namespace)
			fprintf(fh, "%s.", fmtId(te->namespace));
		fprintf(fh, "%s ", fmtId(te->tag));

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
		/* Chop "DROP " off the front and make a modifyable copy */
		char *first = pg_strdup(te->dropStmt + 5);
		char *last;

		/* strip off any ';' or '\n' at the end */
		last = first + strlen(first) - 1;
		while (last >= first && (*last == '\n' || *last == ';'))
			last--;
		*(last + 1) = '\0';		

		fprintf(fh, "%s ", first);

		free(first);

		return;
	}

	exit_horribly(modulename, "don't know how to set owner for object type %s\n", type);
}

static void
add_ownership_information(ArchiveHandle *AH, TocEntry *te, FILE *fh)
{
	/* skip objects that don't have an owner */
	if (strcmp(te->desc, "ACL") == 0 ||
		strcmp(te->desc, "COMMENT") == 0 ||
		strcmp(te->desc, "CONSTRAINT") == 0 ||
		strcmp(te->desc, "DEFAULT") == 0 ||
		strcmp(te->desc, "ENCODING") == 0 ||
		strcmp(te->desc, "EXTENSION") == 0 ||
		strcmp(te->desc, "FK CONSTRAINT") == 0 ||
		strcmp(te->desc, "SEQUENCE OWNED BY") == 0 ||
		strcmp(te->desc, "STDSTRINGS") == 0 ||
		strcmp(te->desc, "TRIGGER") == 0)
		return;

	fprintf(fh, "ALTER ");
	get_object_description(AH, te, fh);
	fprintf(fh, "OWNER TO %s;\n\n", fmtId(te->owner));
}

static void
set_search_path(ArchiveHandle *AH, TocEntry *te, FILE *fh)
{
	if (!te->namespace)
		return;

	/*
	 * We want to add the namespace to information to each object regardless
	 * of the previous object's namespace; that way it is easy to see when an
	 * object is moved to another schema.
	 */
	if (strcmp(te->namespace, "pg_catalog") == 0)
		fprintf(fh, "SET search_path TO pg_catalog;\n\n");
	else
		fprintf(fh, "SET search_path TO %s, pg_catalog;\n\n", fmtId(te->namespace));
}

static void
write_split_directory(ArchiveHandle *AH)
{
	TocEntry *te;
	FILE *indexFH;

	create_sorted_toc(AH);

	indexFH = fopen(prepend_directory(AH, "index.sql"), "w");
	if (!indexFH)
		exit_horribly(modulename, "could not open index.sql: %s\n", strerror(errno));

	fprintf(indexFH, "\n-- PostgreSQL split database dump\n\n");
	fprintf(indexFH, "BEGIN;\n");
	fprintf(indexFH, "SET client_min_messages TO 'warning';\n");
	fprintf(indexFH, "SET client_encoding TO '%s';\n", pg_encoding_to_char(AH->public.encoding));
	fprintf(indexFH, "SET check_function_bodies TO false;\n\n");

	for (te = AH->toc->next; te != AH->toc; te = te->next)
	{
		FILE *fh;
		lclTocEntry *tctx;
		const char *filename;

		tctx = (lclTocEntry *) te->formatData;

		/* skip data */
		if (te->dataDumper)
			continue;

		/* we need to skip this entry, see _ArchiveEntry() */
		if (!tctx->filename)
			continue;

		/* special case: don't try to re-create the "public" schema */
		if (strcmp(te->desc, "SCHEMA") == 0 &&
			strcmp(te->tag, "public") == 0)
			continue;

		filename = prepend_directory(AH, tctx->filename);

		fh = fopen(filename, "a");
		if (!fh)
			exit_horribly(modulename, "could not open file \"%s\": %s\n",
							filename, strerror(errno));

		set_search_path(AH, te, fh);

		fprintf(fh, "%s\n", te->defn);

		add_ownership_information(AH, te, fh);

		fclose(fh);

		if (should_add_index_entry(AH, te))
			fprintf(indexFH, "\\i %s\n", tctx->filename);
	}

	fprintf(indexFH, "COMMIT;\n");
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
	 * "name" datatype, so this should never happen.
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
		{ "AGGREGATE",		"AGGREGATES"		},
		{ "CONSTRAINT",		"CONSTRAINTS"		},
		{ "EXTENSION",		"EXTENSIONS"		},
		{ "FK CONSTRAINT",	"FK_CONSTRAINTS"	},
		{ "INDEX",			"INDEXES"			},
		{ "SEQUENCE",		"SEQUENCES"			},
		{ "TABLE",			"TABLES"			},
		{ "TYPE",			"TYPES"				},
		{ "TRIGGER",		"TRIGGERS"			},
		{ "VIEW",			"VIEWS"				}
	};

	/*
	 * There's no need to create a database; one should always exist when
	 * restoring.
	 */
	if (strcmp(te->desc, "DATABASE") == 0)
		return NULL;

	/* for schemas, create the directory */
	if (strcmp(te->desc, "SCHEMA") == 0)
		create_schema_directory(AH, te->tag);

	if (strcmp(te->desc, "BLOBS") == 0)
		return pg_strdup("blobs.toc");

	if (strcmp(te->desc, "SCHEMA") == 0 ||
		strcmp(te->desc, "ENCODING") == 0 ||
		strcmp(te->desc, "PROCEDURAL LANGUAGE") == 0 ||
		strcmp(te->desc, "STDSTRINGS") == 0)
		return pg_strdup("dbwide.sql");

	/*
	 * We unfortunately don't know which tables the DEFAULT values go to, so we
	 * just add them in after the data has been restored.  It would be nice to
	 * fix this at some point..
	 */
	if (strcmp(te->desc, "DEFAULT") == 0)
		return pg_strdup("postdata.sql");

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
		DumpId depId;

		if (te->nDeps != 1)
			exit_horribly(modulename, "unexpected number of dependencies (%d) for \"%s\" %d\n", te->nDeps, te->desc, te->dumpId);

		depId = *te->dependencies;
		for (depte = te->prev; depte != te; depte = depte->prev)
		{
			if (depte->dumpId == depId)
			{
				lclTocEntry *depentry = (lclTocEntry *) depte->formatData;

				/* XXX should this happen? */
				if (!depentry)
					return NULL;
				
				/*
				 * No need to strdup since depentry's filename is either NULL or an
				 * strdup()'d string.
				 */
				return depentry->filename;
			}
		}

		exit_horribly(modulename, "could not find dependency %d for \"%s\" %d\n", depId, te->desc, te->dumpId);
	}

	if (strcmp(te->desc, "FUNCTION") == 0)
	{
		char *buf;
		char *proname;
		char *p;

		/*
		 * Parse the actual function name from the tag.  This is a bit tricky since
		 * the argument type names could contain any non-null character inside double
		 * quotes.
		 *
		 * Start parsing from the end of the tag; starting from the beginning would be
		 * almost impossible since the function name doesn't have the quotes; we
		 * wouldn't know where the name ends and the argument list starts.
		 */
		buf = pg_strdup(te->dropStmt);
		if (strncmp(buf, "DROP FUNCTION ", 14) != 0)
			exit_horribly(modulename, "could not parse DROP statement \"%s\"\n", te->dropStmt);

		proname = buf + 14;

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

		snprintf(path, MAXPGPATH, "%s/FUNCTIONS/%s.sql", te->namespace, encode_filename(proname));
		free(buf);
		return pg_strdup(path);
	}

	/* finally, see if it's any of the objects that require no special treatment */
	for (i = 0; i < sizeof(object_types) / sizeof(object_types[0]); ++i)
	{
		if (strcmp(object_types[i][0], te->desc) == 0)
		{
			const char *objsubdir = object_types[i][1];

			if (te->namespace)
				snprintf(path, MAXPGPATH, "%s/%s/%s.sql", te->namespace,
						 objsubdir, encode_filename(te->tag));
			else
				snprintf(path, MAXPGPATH, "%s/%s.sql",
						 objsubdir, encode_filename(te->tag));

			return pg_strdup(path);
		}
	}

	exit_horribly(modulename, "unknown object type \"%s\"\n", te->desc);
}
