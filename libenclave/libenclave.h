//
//  libenclave.h
//  libenclave
//
//  Created by haifisch on 11/9/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface libenclave : NSObject

- (void)enclave_delete_message:(int)message_id;
- (void)enclave_submit_nonce;
- (NSData *)enclave_server_public_key;
- (BOOL)is_enclave_user_public_key_stored:(NSData *)public_key;

@end
