//
//  Common.h
//  Cerberus
//
//  Created by haifisch on 11/11/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#ifndef Common_h
#define Common_h

// Standard includes
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Local libraries
#import "libenclave.h"
#import "libcerberus.h"
#import "Curve25519.h"
#import "AESCrypt.h"
#import "NSData+CommonCrypto.h"

// API Endpoint URL
#define ENDPOINT_URL @"https://env1.suntzusecurity.com/enclave.php"

// C type strings, NSString conversion done later
#define DEFAULT_CONFIG_PATH [NSString stringWithFormat:@"%@/.cerberus/config", NSHomeDirectory()]
#define DEFAULT_PUBLIC_KEY_PATH [NSString stringWithFormat:@"%@/.cerberus/public.key", NSHomeDirectory()]
#define DEFAULT_CERBERUS_PATH [NSString stringWithFormat:@"%@/.cerberus/", NSHomeDirectory()]



#endif /* Common_h */
