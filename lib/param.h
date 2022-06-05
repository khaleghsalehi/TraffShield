//
// Created by khalegh on 6/5/22.
//

#ifndef LIMITER_PARAM_H
#define LIMITER_PARAM_H

int MAX_REQUEST_COUNT = 20; // maximum request per N second
int REQUEST_DIFF = 60; // check (time diff) every N second (above)
int BLOCKING_POLICY_TIME = 60; // attacker wait N second
int MAX_UNBLOCKING = 3;
int REVOKE_BLACK_LIST = 86400; // 24 hr



#endif //LIMITER_PARAM_H
