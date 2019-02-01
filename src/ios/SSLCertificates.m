#import "SSLCertificates.h"
#import <Cordova/CDV.h>
#import <Cordova/CDVPluginResult.h>
#import <CommonCrypto/CommonDigest.h>

@interface CustomURLConnectionDelegate : NSObject <NSURLConnectionDelegate>;

@property (strong, nonatomic) CDVPlugin *_plugin;
@property (strong, nonatomic) NSString *_callbackId;
@property (nonatomic, assign) BOOL _checkInCertChain;
@property (strong, nonatomic) NSArray *_allowedFingerprints;
@property (nonatomic, assign) BOOL sentResponse;

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId checkInCertChain:(BOOL)checkInCertChain allowedFingerprints:(NSArray*)allowedFingerprints;

@end

@implementation CustomURLConnectionDelegate

- (id)initWithPlugin:(CDVPlugin*)plugin callbackId:(NSString*)callbackId checkInCertChain:(BOOL)checkInCertChain allowedFingerprints:(NSArray*)allowedFingerprints
{
    self.sentResponse = FALSE;
    self._plugin = plugin;
    self._callbackId = callbackId;
    // if for some reason this code is called we will still not check the chain because it's insecure
    self._checkInCertChain = TRUE;
    self._allowedFingerprints = allowedFingerprints;
    return self;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection willSendRequestForAuthenticationChallenge:
    (NSURLAuthenticationChallenge*)challenge {

    SecTrustRef trustRef = [[challenge protectionSpace] serverTrust];
    SecTrustEvaluate(trustRef, NULL);

    //[challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    [connection cancel];
    CFIndex count = 1;
    if (self._checkInCertChain) {
        count = SecTrustGetCertificateCount(trustRef);
    }

    NSMutableArray *data = [[NSMutableArray alloc] init];
    for (CFIndex i = 0; i < count; i++)
    {
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, i);
        NSDictionary* dict = [self getCertificateData:certRef];
        [data addObject:dict];
    }
    //NSLog(@"%@",data);
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:data];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    self.sentResponse = TRUE;
}

- (NSDictionary*) getCertificateData: (SecCertificateRef) cert {
    NSData* certData = (__bridge NSData*) SecCertificateCopyData(cert);
    NSData* certSerialNumber = (__bridge NSData*) SecCertificateCopySerialNumberData(cert, nil);
    //NSLog(@"%@",certData);
    //NSLog(@"%@",certSerialNumber);

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(certData.bytes, (CC_LONG)certData.length, digest);//int
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];//3
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        [fingerprint appendFormat:@"%02x ", digest[i]];
    }

    NSUInteger dataLength = [certSerialNumber length];
    NSMutableString *serialNumber = [NSMutableString stringWithCapacity:dataLength*2];
    const unsigned char *dataBytes = [certSerialNumber bytes];
    for (NSInteger idx = 0; idx < dataLength; ++idx) {
        [serialNumber appendFormat:@"%02x", dataBytes[idx]];
    }

    NSMutableDictionary *dict = [[NSMutableDictionary alloc]init];
    dict[@"fingerprint"] = [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    dict[@"serialNumber"] = [serialNumber stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    // NSLog(@"%@",dict);

    return dict;
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return nil;
}

// Delegate method, called from connectionWithRequest
- (void) connection: (NSURLConnection*)connection didFailWithError: (NSError*)error {
    connection = nil;
    NSString *resultCode = @"CONNECTION_FAILED. Details:";
    NSString *errStr = [NSString stringWithFormat:@"%@ %@", resultCode, [error localizedDescription]];
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:errStr];
    [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    connection = nil;
    if (![self sentResponse]) {
        NSLog(@"Connection was not checked because it was cached. Considering it secure to not break your app.");
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTION_SECURE"];
        [self._plugin.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

- (BOOL) isFingerprintTrusted: (NSString*)fingerprint {
    for (NSString *fp in self._allowedFingerprints) {
        if ([fingerprint caseInsensitiveCompare: fp] == NSOrderedSame) {
            return YES;
        }
    }
    return NO;
}

@end


@interface SSLCertificates ()

@property (strong, nonatomic) NSString *_callbackId;
@property (strong, nonatomic) NSMutableData *_connections;

@end

@implementation SSLCertificates

- (void)check:(CDVInvokedUrlCommand*)command {

    int cacheSizeMemory = 0*4*1024*1024; // 0MB
    int cacheSizeDisk = 0*32*1024*1024; // 0MB
    NSURLCache *sharedCache = [[NSURLCache alloc] initWithMemoryCapacity:cacheSizeMemory diskCapacity:cacheSizeDisk diskPath:@"nsurlcache"];
    [NSURLCache setSharedURLCache:sharedCache];

    NSString *serverURL = [command.arguments objectAtIndex:0];
    //NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL]];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:serverURL] cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:0.0];

    CustomURLConnectionDelegate *delegate = [[CustomURLConnectionDelegate alloc] initWithPlugin:self//No cambiar self por plugin ya que deja de funcionar
                                                                                     callbackId:command.callbackId
                                                                               checkInCertChain:[[command.arguments objectAtIndex:1] boolValue]
                                                                            allowedFingerprints:[command.arguments objectAtIndex:2]];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];

    if(![[NSURLConnection alloc]initWithRequest:request delegate:delegate]){
        //if (![NSURLConnection connectionWithRequest:request delegate:delegate]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_JSON_EXCEPTION messageAsString:@"CONNECTION_FAILED"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self._callbackId];
    }
}

@end
