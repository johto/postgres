/*-------------------------------------------------------------------------
 *
 * pg_backup_split.c
 *
 * XXX updateme
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
	/*
	 * Our archive location. This is basically what the user specified as his
	 * backup file but of course here it is a directory.
	 */
	char	   *directory;

	cfp		   *dataFH;			/* currently open data file */

	cfp		   *blobsTocFH;		/* file handle for blobs.toc */
} lclContext;

typedef struct
{
	char	   *filename;		/* filename excluding the directory (basename) */
} lclTocEntry;

/* translator: this is a module name */
static const char *modulename = gettext_noop("split archiver");


/* prototypes for private functions */
static void _CreateDirectory(const char *fmt, ...) __attribute__((format(PG_PRINTF_ATTRIBUTE, 1, 2)));
static void _CreateSchemaDirectoryStructure(ArchiveHandle *AH, const char *tag);
static void _ArchiveEntry(ArchiveHandle *AH, TocEntry *te);
static void _StartData(ArchiveHandle *AH, TocEntry *te);
static void _EndData(ArchiveHandle *AH, TocEntry *te);
static size_t _WriteData(ArchiveHandle *AH, const void *data, size_t dLen);
static int	_WriteByte(ArchiveHandle *AH, const int i);
static int	_ReadByte(ArchiveHandle *);
static size_t _WriteBuf(ArchiveHandle *AH, const void *buf, size_t len);
static void _CloseArchive(ArchiveHandle *AH);

static void _WriteIndexFile(ArchiveHandle *AH);

static void _StartBlobs(ArchiveHandle *AH, TocEntry *te);
static void _StartBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);
static void _EndBlob(ArchiveHandle *AH, TocEntry *te, Oid oid);
static void _EndBlobs(ArchiveHandle *AH, TocEntry *te);

static char *prependDirectory(ArchiveHandle *AH, const char *relativeFilename);


/* XXX move me */
static void
_CreateDirectory(const char *fmt, ...)
{
	char directory[MAXPGPATH];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(directory, MAXPGPATH, fmt, ap);
	if (mkdir(directory, 0700) < 0)
		exit_horribly(modulename, "could not create directory \"%s\": %s\n",
					  directory, strerror(errno));
	va_end(ap);
}


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

	/* Initialize LO buffering */
	AH->lo_buf_size = LOBBUFSIZE;
	AH->lo_buf = (void *) pg_malloc(LOBBUFSIZE);

	if (!AH->fSpec || strcmp(AH->fSpec, "") == 0)
		exit_horribly(modulename, "no output directory specified\n");

	ctx->directory = AH->fSpec;

	if (AH->mode == archModeWrite)
	{
		_CreateDirectory("%s", ctx->directory);
		_CreateDirectory("%s/EXTENSIONS", ctx->directory);
	}
	else
        exit_horribly(modulename, "reading a split archive not supported; restore using psql\n");
}

static void
_CreateSchemaDirectoryStructure(ArchiveHandle *AH, const char *tag)
{
	lclContext *ctx = (lclContext *) AH->formatData;
	char	   *dname;

	dname = ctx->directory;
	
	_CreateDirectory("%s/%s", dname, tag);
	_CreateDirectory("%s/%s/FUNCTIONS", dname, tag);
	_CreateDirectory("%s/%s/TABLES", dname, tag);
	_CreateDirectory("%s/%s/INDEXES", dname, tag);
	_CreateDirectory("%s/%s/SEQUENCES", dname, tag);
	_CreateDirectory("%s/%s/VIEWS", dname, tag);
	_CreateDirectory("%s/%s/CONSTRAINTS", dname, tag);
	_CreateDirectory("%s/%s/FK_CONSTRAINTS", dname, tag);
	_CreateDirectory("%s/%s/TYPES", dname, tag);
	_CreateDirectory("%s/%s/TRIGGERS", dname, tag);
	_CreateDirectory("%s/%s/AGGREGATES", dname, tag);
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
	te->formatData = (void *) tctx;

	if (te->dataDumper)
	{
		snprintf(fn, MAXPGPATH, "%s/TABLES/%d.dat", te->namespace, te->dumpId);
		tctx->filename = pg_strdup(fn);
		return;
	}

	if (strcmp(te->desc, "BLOBS") == 0)
	{
		tctx->filename = pg_strdup("blobs.toc");
		return;
	}

	if (strcmp(te->desc, "SCHEMA") == 0)
	{
		_CreateSchemaDirectoryStructure(AH, te->tag);
		tctx->filename = pg_strdup("dbwide.sql");
		return;
	}
	
	if (strcmp(te->desc, "ENCODING") == 0 ||
		strcmp(te->desc, "PROCEDURAL LANGUAGE") == 0 ||
		strcmp(te->desc, "STDSTRINGS") == 0)
	{
		tctx->filename = pg_strdup("dbwide.sql");
		return;
	}

	if (strcmp(te->desc, "DEFAULT") == 0)
	{
		tctx->filename = pg_strdup("postdata.sql");
		return;
	}

	if (strcmp(te->desc, "DATABASE") == 0)
	{
		/* not needed */
		tctx->filename = NULL;
		return;
	}

	if (strcmp(te->desc, "TABLE") == 0 || strcmp(te->desc, "SEQUENCE") == 0 ||
		strcmp(te->desc, "VIEW") == 0 || strcmp(te->desc, "CONSTRAINT") == 0 ||
		strcmp(te->desc, "TYPE") == 0 || strcmp(te->desc, "TRIGGER") == 0 ||
		strcmp(te->desc, "AGGREGATE") == 0)
	{
		snprintf(fn, MAXPGPATH, "%s/%sS/%s.sql", te->namespace, te->desc, te->tag);
		tctx->filename = pg_strdup(fn);
		return;
	}

	if (strcmp(te->desc, "FK CONSTRAINT") == 0)
	{
		snprintf(fn, MAXPGPATH, "%s/FK_CONSTRAINTS/%s.sql", te->namespace, te->tag);
		tctx->filename = pg_strdup(fn);
		return;
	}

	if (strcmp(te->desc, "INDEX") == 0)
	{
		/* XXX if we ever want indexes to be dumped into the table file, we need to
		 * parse the actual definition. ugly :-( */
		snprintf(fn, MAXPGPATH, "%s/INDEXES/%s.sql", te->namespace, te->tag);
		tctx->filename = pg_strdup(fn);
		return;
	}

	if (strcmp(te->desc, "EXTENSION") == 0)
	{
		snprintf(fn, MAXPGPATH, "EXTENSIONS/%s.sql", te->tag);
		tctx->filename = pg_strdup(fn);
		return;
	}
		
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
				const char *depfilename;
				lclTocEntry *depentry = (lclTocEntry *) depte->formatData;

				if (!depentry)
					depfilename = NULL;
				else
					depfilename = depentry->filename;

				if (!depfilename)
					tctx->filename = NULL;
				else
					tctx->filename = pg_strdup(depfilename);

				return;
			}
		}

		exit_horribly(modulename, "could not find dependency %d for \"%s\" %d\n", depId, te->desc, te->dumpId);
	}
	
	if (strcmp(te->desc, "FUNCTION") == 0)
	{
		char *proname;
		char *proArgPos;
	
		/* XXX fix this later */
		proArgPos = strstr(te->tag, "(");
		if (!proArgPos)
			exit_horribly(modulename, "shouldn't happen I think\n");
		proname = strndup(te->tag, proArgPos - te->tag);

		snprintf(fn, MAXPGPATH, "%s/FUNCTIONS/%s.sql", te->namespace, proname);
		tctx->filename = pg_strdup(fn);

		return;
	}

	tctx->filename = NULL;
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

	//fprintf(stderr, "_StartData %s.%s\n", te->namespace, te->tag);

	fname = prependDirectory(AH, tctx->filename);

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
		_WriteIndexFile(AH);
	}
}


static void
_WriteIndexFile(ArchiveHandle *AH)
{
	TocEntry *te;

	for (te = AH->toc->next; te != AH->toc; te = te->next)
	{
		FILE *fh;
		lclTocEntry *tctx;
		const char *filename;

		tctx = (lclTocEntry *) te->formatData;

		/* skip data */
		if (te->dataDumper)
			continue;

		if (!tctx->filename)
		{
			/* only DATABASE is safe to skip */
			if (strcmp(te->desc, "DATABASE") != 0)
				exit_horribly(modulename, "I don't know where to dump \"%s\". Sorry.\n", te->desc);

			continue;
		}

		filename = prependDirectory(AH, tctx->filename);

		fh = fopen(filename, "a");
		if (!fh)
			exit_horribly(modulename, "could not open file \"%s\": %s\n",
							filename, strerror(errno));

		fprintf(fh, "%s\n", te->defn);
		fclose(fh);
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

	fname = prependDirectory(AH, "blobs.toc");

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


static char *
prependDirectory(ArchiveHandle *AH, const char *relativeFilename)
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
