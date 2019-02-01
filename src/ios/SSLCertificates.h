#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface SSLCertificates : CDVPlugin

- (void)check:(CDVInvokedUrlCommand*)command;

@end