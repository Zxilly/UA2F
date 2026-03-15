#ifndef UA2F_HTTP_PARSER_UA_H
#define UA2F_HTTP_PARSER_UA_H

#include "http_session.h"

// Initialize llhttp parser and callbacks on a session.
void http_parser_init_session(struct http_session *session);

// Feed TCP payload to llhttp parser. Updates session->ua_entries.
// Returns: 0 on success, -1 on parse error.
int http_parser_feed(struct http_session *session, const char *data, size_t len);

#endif /* UA2F_HTTP_PARSER_UA_H */
