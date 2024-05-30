#ifndef IO_URING_H
#define IO_URING_H

#include "server.h"

/* Initialize io_uring at server startup if have io_uring configured, setup io_uring submission and completion. */
void initIOUring(void);

/* If the client is suitable to use io_uring handle the write request. */
int useIOUring(client *c);

/* Use io_uring to handle the client request, it is always used together with useIOUring(). */
int writeToClientUsingIOUring(client *c);

/* Submit requests to the submission queue and wait for completion. */
void submitAndWaitIOUringComplete(void);

/* Free io_uring. */
void freeIOUring(void);

#endif /* IO_URING_H */
