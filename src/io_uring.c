#include "io_uring.h"

#ifdef HAVE_LIBURING
#include <liburing.h>

/* io_uring instance queue depth. */
#define IO_URING_DEPTH 256

static size_t io_uring_queue_len = 0;

void initIOUring(void) {
    if (server.io_uring_enabled) {
        struct io_uring_params params;
        struct io_uring *ring = zmalloc(sizeof(struct io_uring));
        memset(&params, 0, sizeof(params));
        /* On success, io_uring_queue_init_params(3) returns 0 and ring will
         * point to the shared memory containing the io_uring queues.
         * On failure -errno is returned. */
        int ret = io_uring_queue_init_params(IO_URING_DEPTH, ring, &params);
        if (ret != 0) {
            /* Warning if user enable the io_uring in config but system doesn't support yet. */
            serverLog(LL_WARNING, "System doesn't support io_uring, disable io_uring.");
            zfree(ring);
            server.io_uring = NULL;
        } else {
            serverLog(LL_NOTICE, "System support io_uring, enable io_uring.");
            server.io_uring = ring;
        }
    }
}

int writeUsingIOUring(client *c) {
    if (server.io_uring_enabled && server.io_uring) {
        /* Currently, we only use io_uring to handle the static buffer write requests. */
        return getClientType(c) != CLIENT_TYPE_SLAVE && listLength(c->reply) == 0 && c->bufpos > 0;
    }
    return 0;
}

int writeToClientUsingIOUring(client *c) {
    c->flags |= CLIENT_PENDING_IO_URING_WRITE;
    struct io_uring_sqe *sqe = io_uring_get_sqe(server.io_uring);
    if (sqe == NULL) return C_ERR;
    io_uring_prep_send(sqe, c->conn->fd, c->buf + c->sentlen, c->bufpos - c->sentlen, MSG_DONTWAIT);
    io_uring_sqe_set_data(sqe, c);
    io_uring_queue_len++;
    return C_OK;
}

/* Submit requests to the submission queue and wait for completion. */
static inline void ioUringSubmitAndWaitBarrier(void) {
    io_uring_submit(server.io_uring);
    /* Wait for all submitted queue entries complete. */
    while (io_uring_queue_len) {
        struct io_uring_cqe *cqe;
        if (io_uring_wait_cqe(server.io_uring, &cqe) == 0) {
            client *c = io_uring_cqe_get_data(cqe);
            c->nwritten = cqe->res;
            io_uring_cqe_seen(server.io_uring, cqe);
            io_uring_queue_len--;
        } else {
            serverPanic("Error waiting io_uring completion queue.");
        }
    }
}

/* Check the completed io_uring event and update the state. */
int checkPendingIOUringWriteState(client *c) {
    /* Note that where synchronous system calls will return -1 on
     * failure and set errno to the actual error value,
     * io_uring never uses errno. Instead it returns the negated
     * errno directly in the CQE res field. */
    if (c->nwritten <= 0) {
        if (c->nwritten != -EAGAIN) {
            c->conn->last_errno = -(c->nwritten);
            /* Don't overwrite the state of a connection that is not already
             * connected, not to mess with handler callbacks. */
            if (c->nwritten != -EINTR && c->conn->state == CONN_STATE_CONNECTED) c->conn->state = CONN_STATE_ERROR;
        }
        if (connGetState(c->conn) != CONN_STATE_CONNECTED) {
            serverLog(LL_VERBOSE, "Error writing to client: %s", connGetLastError(c->conn));
            freeClientAsync(c);
        }
        return C_ERR;
    }

    c->sentlen += c->nwritten;
    /* If the buffer was sent, set bufpos to zero to continue with
     * the remainder of the reply. */
    if ((int)c->sentlen == c->bufpos) {
        c->bufpos = 0;
        c->sentlen = 0;
    }
    atomic_fetch_add_explicit(&server.stat_net_output_bytes, c->nwritten, memory_order_relaxed);
    c->net_output_bytes += c->nwritten;

    /* For clients representing masters we don't count sending data
     * as an interaction, since we always send REPLCONF ACK commands
     * that take some time to just fill the socket output buffer.
     * We just rely on data / pings received for timeout detection. */
    if (!(c->flags & CLIENT_MASTER)) c->lastinteraction = server.unixtime;

    return C_OK;
}

void submitAndWaitIOUringComplete() {
    if (server.io_uring_enabled && server.io_uring && listLength(server.clients_pending_write) > 0) {
        ioUringSubmitAndWaitBarrier();
        listIter li;
        listNode *ln;
        /* An optimization for connWrite: batch submit the write(3). */
        listRewind(server.clients_pending_write, &li);
        while ((ln = listNext(&li))) {
            client *c = listNodeValue(ln);
            c->flags &= ~CLIENT_PENDING_IO_URING_WRITE;
            listUnlinkNode(server.clients_pending_write, ln);

            if (checkPendingIOUringWriteState(c) == C_ERR) continue;
            if (!clientHasPendingReplies(c)) {
                c->sentlen = 0;
                /* Close connection after entire reply has been sent. */
                if (c->flags & CLIENT_CLOSE_AFTER_REPLY) {
                    freeClientAsync(c);
                    continue;
                }
            }
            /* Update client's memory usage after writing.
             * Since this isn't thread safe we do this conditionally. In case of threaded writes this is done in
             * handleClientsWithPendingWritesUsingThreads(). */
            if (io_threads_op == IO_THREADS_OP_IDLE) updateClientMemUsageAndBucket(c);
        }
    }
}

void freeIOUring(void) {
    if (server.io_uring_enabled && server.io_uring) {
        io_uring_queue_exit(server.io_uring);
        zfree(server.io_uring);
        server.io_uring = NULL;
    }
}
#else
void initIOUring(void) {
}

int writeUsingIOUring(client *c) {
    UNUSED(c);
    return 0;
}

int writeToClientUsingIOUring(client *c) {
    UNUSED(c);
    return 0;
}

void submitAndWaitIOUringComplete(void) {
}

void freeIOUring(void) {
}
#endif /* IO_URING_H */
