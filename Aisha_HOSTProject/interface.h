// ========================================================================================================
// ========================================================================================================
// ******************************************* interface.h ************************************************
// ========================================================================================================
// ========================================================================================================

#ifndef SRC_INTERFACE_H_
#define SRC_INTERFACE_H_

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include "common.h"

#define false 0
#define true 1

#define MENU_WITHDRAW 0 
#define MENU_TRANSFER 1
#define MENU_RECEIVE 2 
#define MENU_DEPOSIT 3 
#define MENU_GET_AT 4 
#define MENU_ACCOUNT 5
#define MENU_KEKSEND 6
#define MENU_KEKRECEIVE 7
#define MENU_LOCK 8
#define MENU_NOOP 9

#define TRANSFER_WITHDRAW 0
#define TRANSFER_SEND 1
#define TRANSFER_RECEIVE 2
#define TRANSFER_DEPOSIT 3


void show_account(int alice_balance, int bob_total);

int main_menu(int main_menu_blocks, int iteration);

int get_withdraw();
void withdraw_fail();
void withdraw_success(unsigned int amount);

struct transfer get_transfer();
void transfer_fail();
void transfer_success(struct transfer request);

int receive_wait(int firstTime);
void receive_fail();
void receive_success(struct transfer receipt);

int get_deposit();
void deposit_fail();
void deposit_success(unsigned int amount);

#endif
