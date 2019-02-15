
#include <http_comm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NEXTID(idx,size)  (((idx)+1)%(size))
#define FREED     0
#define ALLOCATED 1

static int  CTX_START_ID[MAX_THRD_NUM];		/* start and end Id of each Process */
static int  CTX_SIZEID[MAX_THRD_NUM];		/* start and end Id of each Process */
int			CTX_NUM_FREEIDS[MAX_THRD_NUM];
static int 	CTX_NEXT_FREEID[MAX_THRD_NUM];
static char	CTX_USED_TAG[MAX_THRD_NUM][MAXMSG+1];

int	Init_CtxId(int thrd_idx)
{
	CTX_START_ID[thrd_idx] = STARTID;
	CTX_SIZEID[thrd_idx]  = SIZEID-1;
	CTX_NEXT_FREEID[thrd_idx] = 0;
	CTX_NUM_FREEIDS[thrd_idx] = CTX_SIZEID[thrd_idx];

	memset((char *)CTX_USED_TAG, 0x00, CTX_SIZEID[thrd_idx]);
	return (0);
}
int	Get_CtxId(int thrd_idx)
{
	int i, idx;

#if 0
	/* no available Id */
	if (CTX_NUM_FREEIDS[thrd_idx] <= 0)
		return -1;
#endif

	/* find freed Id */
	for (i=0, idx=CTX_NEXT_FREEID[thrd_idx]; i<CTX_SIZEID[thrd_idx]; i++) {
		if (CTX_USED_TAG[thrd_idx][idx] == FREED)
		{
			CTX_USED_TAG[thrd_idx][idx] = ALLOCATED;
			CTX_NEXT_FREEID[thrd_idx] = NEXTID(idx, CTX_SIZEID[thrd_idx]);
			(CTX_NUM_FREEIDS[thrd_idx])--;
			return (idx+CTX_START_ID[thrd_idx]);
		}
		idx = NEXTID(idx, CTX_SIZEID[thrd_idx]);
	}
	return (-1);
}
int	Free_CtxId(int thrd_idx, uint id)
{
	if((id<CTX_START_ID[thrd_idx]) || (id>=(CTX_START_ID[thrd_idx]+CTX_SIZEID[thrd_idx])))
		return(-1);

#if 0
	(CTX_NUM_FREEIDS[thrd_idx])++;
	CTX_USED_TAG[thrd_idx][id-CTX_START_ID[thrd_idx]] = FREED;
#else
	if (CTX_USED_TAG[thrd_idx][id-CTX_START_ID[thrd_idx]] != FREED) {
		(CTX_NUM_FREEIDS[thrd_idx])++;
		CTX_USED_TAG[thrd_idx][id-CTX_START_ID[thrd_idx]] = FREED;
	}
#endif

	return(0);
}
int Check_CtxId(int thrd_idx, uint id)
{
	if((id<CTX_START_ID[thrd_idx]) || (id>=(CTX_START_ID[thrd_idx]+CTX_SIZEID[thrd_idx])))
		return(-1);

	return(0);
}
