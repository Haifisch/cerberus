//
//  main.m
//  Cerberus
//
//  Created by haifisch on 11/6/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Common.h"

#define PRGM_VER "v1.0.1"

libenclave *enclave_api;
libcerberus *cerberus_instance;
AESCrypt *crypt_instance;

// message queue method
void check_server_for_messages() {
}

// message queue method
void delete_message_with_id(int message_id) {
    [enclave_api enclave_delete_message:message_id];
    
    exit(0);
}

void print_help() {
    // header
    printf("-----------------------\n");
    printf(":::     Cerberus    :::\n");
    printf("::: Enclave Console :::\n");
    printf("-----------------------\n");
    printf("::: Version; %s\n", PRGM_VER);
    printf("::: Built; %s\n", __DATE__);
    printf("-----------------------\n");
    // options
    printf("Config storage is in ~/.cerberus by default\n");
    printf("Options;\n");
    printf("0 -- exit client\n");
    printf("1 -- check queued messages on server\n");
    printf("2 -- delete message\n");
    printf("3 -- read encrypted message (returns data in base64)\n");
    printf("4 -- send text message\n");
    
}



int main(int argc, const char * argv[]) {
    @autoreleasepool {
        int input, inputBuffer;
        char boolin, boolBuffer;
        enclave_api = [[libenclave alloc] init];
        crypt_instance = [[AESCrypt alloc] init];
        cerberus_instance = [[libcerberus alloc] init];
        
        if (![cerberus_instance cerberus_check_for_config]) { // check if config exists
            printf("No previous config found, would you like to create a new one? (y\n)\n>");
            boolin = scanf(" %c", &boolBuffer);
            if (boolBuffer == 'y') {
                [cerberus_instance cerberus_setup_config];
            } else {
                printf("Canceling...\n");
            }

        }
        
        printf("Checking for existing public key on server...\n");
        if (![enclave_api is_enclave_user_public_key_stored:[cerberus_instance cerberus_user_public_key]]) {
            printf("No public key is stored on the server.\n");
        } else {
            printf("Existing public key is stored on the server.\n");
        }
        
        print_help(); // intro into console
        
        NSData *server_pub = [enclave_api enclave_server_public_key];
        printf("Jumping into console\n");
        while (1) {
            printf(">");
            input = scanf("%d", &inputBuffer);
            if (input == EOF) {
                /* Handle EOF/Failure */
                exit(0);
            } else if (input == 0) {
                /* Handle no match */
                exit(0);
            } else {
                switch ((int)inputBuffer) {
                    case 0:
                        exit(0);
                        break;
                    
                    case 1:
                        check_server_for_messages();
                        break;
                        
                    case 2:
                        printf("What message ID should I delete?\n>");
                        input = scanf("%d", &inputBuffer);
                        printf("Are you sure you want to delete message with ID -- %d? (y/n)\n>", inputBuffer);
                        boolin = scanf(" %c", &boolBuffer);
                        if (boolBuffer == 'y') {
                            delete_message_with_id(inputBuffer);
                        } else {
                            printf("Canceling...\n");
                        }
                        break;
                        
                    default:
                        printf("%d is an invalid operation\n", inputBuffer);
                        break;
                }
            }
            printf("\n");
            inputBuffer = 0;
        }
    }
    return 0;
}
