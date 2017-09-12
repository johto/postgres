/*-------------------------------------------------------------------------
 *
 * nodeSeqscan.c
 *	  Support routines for sequential scans of relations.
 *
 * Portions Copyright (c) 1996-2011, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/nodeSeqscan.c
 *
 *-------------------------------------------------------------------------
 */
/*
 * INTERFACE ROUTINES
 *		ExecSeqScan				sequentially scans a relation.
 *		ExecSeqNext				retrieve next tuple in sequential order.
 *		ExecInitSeqScan			creates and initializes a seqscan node.
 *		ExecEndSeqScan			releases any storage allocated.
 *		ExecReScanSeqScan		rescans the relation
 *		ExecSeqMarkPos			marks scan position
 *		ExecSeqRestrPos			restores scan position
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/relscan.h"
#include "executor/execdebug.h"
#include "executor/nodeSeqscan.h"

static void InitScanRelation(SeqScanState *node, EState *estate);
static TupleTableSlot *SeqNext(SeqScanState *node);

/* ----------------------------------------------------------------
 *						Scan Support
 * ----------------------------------------------------------------
 */

/* ----------------------------------------------------------------
 *		SeqNext
 *
 *		This is a workhorse for ExecSeqScan
 * ----------------------------------------------------------------
 */
static TupleTableSlot *
SeqNext(SeqScanState *node)
{
	TupleTableSlot *slot;

	if (node->currentScanTuple < 0)
	{
		HeapTuple	tuple;
		HeapScanDesc scandesc = node->ss.ss_currentScanDesc;
		EState	   *estate = node->ss.ps.state;
		ScanDirection direction = estate->es_direction;
		int i;
		int numTupleSlots;
		int numMinShuffleTupleSlot = 0;

		for (i = 0; i < sizeof(node->scanTupleSlots) / sizeof(node->scanTupleSlots[0]); ++i)
		{
			/*
			 * get the next tuple from the table
			 */
			tuple = heap_getnext(scandesc, direction);

			/*
			 * save the tuple and the buffer returned to us by the access methods in
			 * our scan tuple slot and return the slot.  Note: we pass 'false' because
			 * tuples returned by heap_getnext() are pointers onto disk pages and were
			 * not created with palloc() and so should not be pfree()'d.  Note also
			 * that ExecStoreTuple will increment the refcount of the buffer; the
			 * refcount will not be dropped until the tuple table slot is cleared.
			 */
			if (tuple)
			{
				TupleTableSlot *scanSlot = node->ss.ss_ScanTupleSlot;

				ExecStoreTuple(tuple,	/* tuple to store */
							   scanSlot,	/* slot to store in */
							   scandesc->rs_cbuf,		/* buffer associated with this
														 * tuple */
							   false);	/* don't pfree this pointer */
				ExecCopySlot(node->scanTupleSlots[i], scanSlot);
				ExecClearTuple(scanSlot);
			}
			else
			{
				if (i > 0)
				{
					TupleTableSlot *tmp = node->scanTupleSlots[0];
					node->scanTupleSlots[0] = node->scanTupleSlots[i];
					node->scanTupleSlots[i] = tmp;
					ExecClearTuple(node->scanTupleSlots[0]);

					numMinShuffleTupleSlot = 1;
				}
				else
					ExecClearTuple(node->scanTupleSlots[0]);

				/* no more tuples */
				i++;
				break;
			}
		}
		numTupleSlots = i;
		for (i = numTupleSlots - 1; i > numMinShuffleTupleSlot; --i)
		{
			int j = numMinShuffleTupleSlot + (random() % (i + 1 - numMinShuffleTupleSlot));
			TupleTableSlot *tmp = node->scanTupleSlots[i];
			node->scanTupleSlots[i] = node->scanTupleSlots[j];
			node->scanTupleSlots[j] = tmp;
		}
		node->currentScanTuple = numTupleSlots - 1;
	}

	slot = node->scanTupleSlots[node->currentScanTuple];
	--node->currentScanTuple;
	return slot;
}

/*
 * SeqRecheck -- access method routine to recheck a tuple in EvalPlanQual
 */
static bool
SeqRecheck(SeqScanState *node, TupleTableSlot *slot)
{
	/*
	 * Note that unlike IndexScan, SeqScan never use keys in heap_beginscan
	 * (and this is very bad) - so, here we do not check are keys ok or not.
	 */
	return true;
}

/* ----------------------------------------------------------------
 *		ExecSeqScan(node)
 *
 *		Scans the relation sequentially and returns the next qualifying
 *		tuple.
 *		We call the ExecScan() routine and pass it the appropriate
 *		access method functions.
 * ----------------------------------------------------------------
 */
TupleTableSlot *
ExecSeqScan(SeqScanState *node)
{
	return ExecScan(&node->ss,
					(ExecScanAccessMtd) SeqNext,
					(ExecScanRecheckMtd) SeqRecheck);
}

/* ----------------------------------------------------------------
 *		InitScanRelation
 *
 *		This does the initialization for scan relations and
 *		subplans of scans.
 * ----------------------------------------------------------------
 */
static void
InitScanRelation(SeqScanState *node, EState *estate)
{
	Relation	currentRelation;
	HeapScanDesc currentScanDesc;
	int i;

	/*
	 * get the relation object id from the relid'th entry in the range table,
	 * open that relation and acquire appropriate lock on it.
	 */
	currentRelation = ExecOpenScanRelation(estate,
									 ((SeqScan *) node->ss.ps.plan)->scanrelid);

	currentScanDesc = heap_beginscan(currentRelation,
									 estate->es_snapshot,
									 0,
									 NULL);

	node->ss.ss_currentRelation = currentRelation;
	node->ss.ss_currentScanDesc = currentScanDesc;

	for (i = 0; i < sizeof(node->scanTupleSlots) / sizeof(node->scanTupleSlots[0]); ++i)
		ExecSetSlotDescriptor(node->scanTupleSlots[i], RelationGetDescr(currentRelation));
	ExecAssignScanType(&node->ss, RelationGetDescr(currentRelation));
}


/* ----------------------------------------------------------------
 *		ExecInitSeqScan
 * ----------------------------------------------------------------
 */
SeqScanState *
ExecInitSeqScan(SeqScan *node, EState *estate, int eflags)
{
	SeqScanState *seqstate;
	ScanState *scanstate;
	int i;

	/*
	 * Once upon a time it was possible to have an outerPlan of a SeqScan, but
	 * not any more.
	 */
	Assert(outerPlan(node) == NULL);
	Assert(innerPlan(node) == NULL);

	/*
	 * create state structure
	 */
	seqstate = makeNode(SeqScanState);
	scanstate = &seqstate->ss;
	scanstate->ps.plan = (Plan *) node;
	scanstate->ps.state = estate;

	/*
	 * Miscellaneous initialization
	 *
	 * create expression context for node
	 */
	ExecAssignExprContext(estate, &scanstate->ps);

	/*
	 * initialize child expressions
	 */
	scanstate->ps.targetlist = (List *)
		ExecInitExpr((Expr *) node->plan.targetlist,
					 (PlanState *) scanstate);
	scanstate->ps.qual = (List *)
		ExecInitExpr((Expr *) node->plan.qual,
					 (PlanState *) scanstate);

	/*
	 * tuple table initialization
	 */
	ExecInitResultTupleSlot(estate, &scanstate->ps);
	ExecInitScanTupleSlot(estate, scanstate);
	for (i = 0; i < sizeof(seqstate->scanTupleSlots) / sizeof(seqstate->scanTupleSlots[0]); ++i)
	{
		seqstate->scanTupleSlots[i] = ExecAllocTableSlot(&estate->es_tupleTable);
	}
	seqstate->currentScanTuple = -1;

	/*
	 * initialize scan relation
	 */
	InitScanRelation(seqstate, estate);

	scanstate->ps.ps_TupFromTlist = false;

	/*
	 * Initialize result tuple type and projection info.
	 */
	ExecAssignResultTypeFromTL(&scanstate->ps);
	ExecAssignScanProjectionInfo(scanstate);

	return seqstate;
}

/* ----------------------------------------------------------------
 *		ExecEndSeqScan
 *
 *		frees any storage allocated through C routines.
 * ----------------------------------------------------------------
 */
void
ExecEndSeqScan(SeqScanState *node)
{
	Relation	relation;
	HeapScanDesc scanDesc;

	/*
	 * get information from node
	 */
	relation = node->ss.ss_currentRelation;
	scanDesc = node->ss.ss_currentScanDesc;

	/*
	 * Free the exprcontext
	 */
	ExecFreeExprContext(&node->ss.ps);

	/*
	 * clean out the tuple table
	 */
	ExecClearTuple(node->ss.ps.ps_ResultTupleSlot);
	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	/*
	 * close heap scan
	 */
	heap_endscan(scanDesc);

	/*
	 * close the heap relation.
	 */
	ExecCloseScanRelation(relation);
}

/* ----------------------------------------------------------------
 *						Join Support
 * ----------------------------------------------------------------
 */

/* ----------------------------------------------------------------
 *		ExecReScanSeqScan
 *
 *		Rescans the relation.
 * ----------------------------------------------------------------
 */
void
ExecReScanSeqScan(SeqScanState *node)
{
	HeapScanDesc scan;

	scan = node->ss.ss_currentScanDesc;

	heap_rescan(scan,			/* scan desc */
				NULL);			/* new scan keys */

	node->currentScanTuple = -1;

	ExecScanReScan(&node->ss);
}

/* ----------------------------------------------------------------
 *		ExecSeqMarkPos(node)
 *
 *		Marks scan position.
 * ----------------------------------------------------------------
 */
void
ExecSeqMarkPos(SeqScanState *node)
{
	/* nobody should ever call this */
	elog(ERROR, "mark on SeqScan attempted");
}

/* ----------------------------------------------------------------
 *		ExecSeqRestrPos
 *
 *		Restores scan position.
 * ----------------------------------------------------------------
 */
void
ExecSeqRestrPos(SeqScanState *node)
{
	/* nobody should ever call this */
	elog(ERROR, "restore on SeqScan attempted");
}
