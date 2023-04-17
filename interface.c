// ========================================================================================================
// ========================================================================================================
// ********************************************** interface.c *********************************************
// ========================================================================================================
// ========================================================================================================

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "interface.h"
#include <poll.h>

extern int usleep (__useconds_t __useconds);

// =============================================================================================================
void show_account(int balance, int pending)
   {
   printf("Current balance %d\tPending %d\n", balance, pending);
   fflush(stdout);
   return;
   }

// =============================================================================================================
int get_withdraw()
   {
   int amt;
   printf("Enter withdraw amount as xxx in cents\n");
   scanf("%d", &amt);
   return amt;
   }

// =============================================================================================================
void withdraw_fail()
   {
   printf("FAILED TO WITHDRAW\n");
   printf("\tReturning to the main menu.\n\n");
   }

// =============================================================================================================
void withdraw_success(unsigned int amount)
   {
   printf("WITHDRAW SUCCESS\n");
   int cents = amount % 100;
   int dollars = amount / 100;
   printf("\tWithdrew $%d.%02d\n", dollars, cents);
   printf("\tReturning to the main menu.\n\n");
   }

// =============================================================================================================
struct transfer get_transfer()
   {
   struct transfer request;
   int amt, id;

   printf("TRANSFER\n");

   printf("Enter request amount as xxx in cents\n");
   scanf("%d", &amt);
   if ( amt == -1 )
      {
      printf("Transfer canceled\n\n");
      request.amount = -1;
      return request;
      }

   printf("Enter Device ID\n");
   scanf("%d", &id);
   if ( id == -1 )
      {
      printf("Transfer canceled\n\n");
      request.amount = -1;
      return request;
      }

   request.amount = amt;
   request.id_to = id;
   request.timestamp = time(NULL);
   request.type = TRANSFER_SEND;

   return request;
   }

// =============================================================================================================
void transfer_fail()
   {
   printf("FAILED TO TRANSFER\n");
   printf("\tReturning to the main menu.\n\n");
   }

// =============================================================================================================
void transfer_success(struct transfer request)
   {
   printf("TRANSFER SUCCESS\n");
   int cents = request.amount % 100;
   int dollars = request.amount / 100;
   printf("\tSent $%d.%02d to ID %d\n", dollars, cents, request.id_to);
   printf("\tReturning to the main menu.\n\n");
   }

// =============================================================================================================
int receive_wait(int firstTime)
   {
   usleep(500000);
   return 0;
   }

// =============================================================================================================
void receive_fail()
   {
   printf("RECEIVE FAILED\n");
   }

// =============================================================================================================
void receive_success(struct transfer receipt)
   {
   printf("RECEIVE SUCCESS\n");
   int cents = receipt.amount % 100;
   int dollars = receipt.amount / 100;
   printf("\tGot $%d.%02d from ID %d\n", dollars, cents, receipt.id_to);
   printf("\tReturning to the main menu.\n\n");
   }

// =============================================================================================================
int get_deposit()
   {
   int amt;

   printf("Enter deposit amount as xxx in cents, first drawn from pending and then from balance\n");
   scanf("%d", &amt);

   return amt;
   }

// =============================================================================================================
void deposit_fail()
   {
   printf("FAILED TO DEPOSIT\n");
   }

// =============================================================================================================
void deposit_success(unsigned int amount)
   {
   printf("DEPOSIT SUCCESS\n");
   int cents = amount % 100;
   int dollars = amount / 100;
   printf("\tDeposited $%d.%02d\n", dollars, cents);
   printf("\tReturning to the main menu.\n\n");
   }
 
// =============================================================================================================
// =============================================================================================================
int main_menu(int main_menu_blocks, int iteration)
   {
   struct pollfd mypoll = {STDIN_FILENO, POLLIN|POLLPRI};
   int menu_select;

// Using poll, https://stackoverflow.com/questions/21197977/how-can-i-prevent-scanf-to-wait-forever-for-an-input-character

   printf("1) WITHDRAW, 2) TRANSFER, 3) RECEIVE, 4) DEPOSIT, 5) ACCOUNT, 6) SEND, 7) RECEIVE, 8) GET ATs (iteration %d)\n", iteration);
   if ( poll(&mypoll, 1, 2000) == 1 || main_menu_blocks == 1 )
      {
      scanf("%d", &menu_select);
      }

   if ( menu_select == 1 )
      return MENU_WITHDRAW;
   else if ( menu_select == 2 )
      return MENU_TRANSFER;
   else if ( menu_select == 3 )
      return MENU_RECEIVE;
   else if ( menu_select == 4 )
      return MENU_DEPOSIT;
   else if ( menu_select == 5 )
      return MENU_ACCOUNT;
   else if ( menu_select == 6 )
      return MENU_KEKSEND;
   else if ( menu_select == 7 )
      return MENU_KEKRECEIVE;
   else if ( menu_select == 8 )
      return MENU_GET_AT;
   else
      return MENU_NOOP; 
   }

// =============================================================================================================
// =============================================================================================================
void load_settings()
   {
   printf("Load Settings called\n");

   return;
   }

// =============================================================================================================
void lock_device(int sleep)
   {
   printf("Lock Device called\n");
   return;
   }
