//
//  libenclave.m
//  libenclave
//
//  Created by haifisch on 11/9/16.
//  Copyright © 2016 haifisch. All rights reserved.
//

#import "libenclave.h"
#import "Common.h"

@implementation libenclave

- (id)init {
    if (self = [super init]) {
        NSLog(@"libenclave initiated...");
        return self;
    } else
        return nil;
}

- (void)enclave_delete_message:(int)message_id {
    
}

- (void)enclave_submit_nonce {
    
}

- (NSURL *)enclave_endpoint_url:(int)opcode {
    NSURL *endpoint;
    switch (opcode) {
        case 0: // request server public key
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=server_pub", ENDPOINT_URL]];
            break;
        
        case 1:
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=check_key", ENDPOINT_URL]];
            break;
            
        case 2:
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=submit_key", ENDPOINT_URL]];
            break;
        
        case 3:
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=check_messages", ENDPOINT_URL]];
            break;

        case 4:
            endpoint = [NSURL URLWithString:[NSString stringWithFormat:@"%@?action=get_pub", ENDPOINT_URL]];
            break;
            
        default:
            return nil;
            break;
    }
    return endpoint;
}

- (NSDictionary *)enclave_request_repsonse:(NSURL *)enclave_url {
    NSData *urlData = [NSData dataWithContentsOfURL:enclave_url];
    if (!urlData) {
        NSLog(@"[libenclave] urlData is null, cannot continue. Returning nil.");
        return nil;
    }
    NSError *error;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:urlData options:0 error:&error];
    if (error || json == nil) {
        NSLog(@"[libenclave] json could not be parsed.");
        return nil;
    }
    return json;
}

- (NSData *)enclave_server_public_key {
    NSDictionary *public_key_reponse = [self enclave_request_repsonse:[self enclave_endpoint_url:0]];
    NSString *public_key_encoded = (NSString*)public_key_reponse[@"result"];
    NSData *public_key_data = [[NSData alloc] initWithBase64EncodedString:public_key_encoded options:0];
    if (public_key_data.length != 32) {
        NSLog(@"[libenclave] size of returned public key is not 32 bytes! something must be wrong... exiting.");
        return nil;
    }
    return public_key_data;
}

- (BOOL)is_enclave_user_public_key_stored:(NSString *)public_key {
    
    public_key = [public_key stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    public_key = [public_key stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    NSString *post = [NSString stringWithFormat:@"user_pub=%@",public_key];
    NSData *postData = [post dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[self enclave_endpoint_url:1]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = postData;
    __block BOOL submitResponse;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error) {
            NSMutableDictionary *parsedDict = [[NSJSONSerialization JSONObjectWithData:data options:0 error:nil] mutableCopy];
            if ([parsedDict[@"error"] integerValue] == 1 || parsedDict == nil) {
                submitResponse = NO;
            }else {
                submitResponse = YES;
            }
        } else {
            submitResponse = NO;
        }
        dispatch_semaphore_signal(semaphore);
    }] resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return submitResponse;
}

- (BOOL)enclave_user_submit_public_key:(NSString *)public_key withKeypair:(ECKeyPair *)keypair {
    NSData *sigData = [Ed25519 sign:[[NSData alloc] initWithBase64EncodedString:public_key options:0] withKeyPair:keypair];
    NSString *sig64 = [sigData base64EncodedStringWithOptions:0];
    
    sig64 = [sig64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    sig64 = [sig64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    public_key = [public_key stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    public_key = [public_key stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    NSString *post = [NSString stringWithFormat:@"user_pub=%@&key_signature=%@",public_key, sig64];
    NSData *postData = [post dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[self enclave_endpoint_url:2]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = postData;
    __block BOOL submitResponse;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error) {
            NSMutableDictionary *parsedDict = [[NSJSONSerialization JSONObjectWithData:data options:0 error:nil] mutableCopy];
            if ([parsedDict[@"error"] integerValue] == 1 || parsedDict == nil) {
                submitResponse = NO;
            }else {
                submitResponse = YES;
            }
        } else {
            submitResponse = NO;
        }
        dispatch_semaphore_signal(semaphore);
    }] resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return submitResponse;
}

- (NSArray *)enclave_user_queue:(NSString *)public_key {
    public_key = [public_key stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    public_key = [public_key stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    NSString *post = [NSString stringWithFormat:@"user_pub=%@",public_key];
    NSData *postData = [post dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[self enclave_endpoint_url:3]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = postData;
    __block NSArray *submitResponse;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error) {
            NSMutableDictionary *parsedDict = [[NSJSONSerialization JSONObjectWithData:data options:0 error:nil] mutableCopy];
            if ([parsedDict[@"error"] integerValue] == 0 || parsedDict != nil) {
                submitResponse = parsedDict[@"msgs"];
            }else {
                submitResponse = NULL;
            }
        } else {
            submitResponse = NULL;
        }
        dispatch_semaphore_signal(semaphore);
    }] resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return submitResponse;
}

- (NSData *)enclave_user_pub:(NSString *)public_key forRecieverID:(NSString *)reciever_id {
    
    public_key = [public_key stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    public_key = [public_key stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    
    NSString *post = [NSString stringWithFormat:@"user_pub=%@&reciever_id=%@",public_key, reciever_id];
    NSData *postData = [post dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[self enclave_endpoint_url:4]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = postData;
    __block NSData *submitResponse;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (!error) {
            NSMutableDictionary *parsedDict = [[NSJSONSerialization JSONObjectWithData:data options:0 error:nil] mutableCopy];
            if ([parsedDict[@"error"] integerValue] == 0 || parsedDict != nil) {
                submitResponse = [[NSData alloc] initWithBase64EncodedString:parsedDict[@"pub"] options:0];
            }else {
                submitResponse = NULL;
            }
        } else {
            submitResponse = NULL;
        }
        dispatch_semaphore_signal(semaphore);
    }] resume];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return submitResponse;
}
@end
