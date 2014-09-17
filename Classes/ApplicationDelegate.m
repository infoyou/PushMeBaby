
#import "ApplicationDelegate.h"

@interface ApplicationDelegate ()
#pragma mark - Properties
@property(nonatomic, retain) NSString *deviceToken, *payload, *certificate;
#pragma mark - Private
- (void)connect;
- (void)disconnect;
@end

@implementation ApplicationDelegate

#pragma mark Properties
@synthesize deviceToken = _deviceToken;
@synthesize payload = _payload;
@synthesize certificate = _certificate;

#pragma mark - Allocation

- (id)init {
	self = [super init];
    
	if(self != nil) {
        isPublish = NO;
        self.deviceToken = @"a619145c bd6c2b0d d616a035 5d6fb4eb 3812f0fa b550d2a4 9ad88b0b 683dc3c9";
//        self.deviceToken = @"e66b8003 2182f95c 6b577a37 666aee83 16d36549 499e946c a6173310 cfb4438a";
        self.payload = @"{\"aps\":{\"alert\":\"This is Test message.\", \"sound\":\"notify.wav\", \"badge\":2}}";
        
        if (!isPublish) {
            self.certificate = [[NSBundle mainBundle] pathForResource:@"aps_dev" ofType:@"cer"];
        } else {
            self.certificate = [[NSBundle mainBundle] pathForResource:@"aps_pro" ofType:@"cer"];
        }
	}
    
	return self;
}

- (void)dealloc {
	
	// Release objects.
	self.deviceToken = nil;
	self.payload = nil;
	self.certificate = nil;
	
	// Call super.
	[super dealloc];
}

#pragma mark - Inherent

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	[self connect];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
	[self disconnect];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)application {
	return YES;
}

#pragma mark - Private

- (void)connect {
	
	if(self.certificate == nil) {
		return;
	}
	
	// Define result variable.
	OSStatus result;
	
	// Establish connection to server.
	PeerSpec peer;
    
    if (!isPublish) {
        result = MakeServerConnection("gateway.sandbox.push.apple.com", 2195, &socket, &peer);
    } else {
        result = MakeServerConnection("gateway.push.apple.com", 2195, &socket, &peer);
	}
    
	// Create new SSL context.
	result = SSLNewContext(false, &context);
	
	// Set callback functions for SSL context.
	result = SSLSetIOFuncs(context, SocketRead, SocketWrite);// NSLog(@"SSLSetIOFuncs(): %d", result);
	
	// Set SSL context connection.
	result = SSLSetConnection(context, socket);// NSLog(@"SSLSetConnection(): %d", result);
	
	// Set server domain name.
    if (!isPublish) {
        result = SSLSetPeerDomainName(context, "gateway.sandbox.push.apple.com", 30);
    } else {
        result = SSLSetPeerDomainName(context, "gateway.push.apple.com", 22);
    }
    // NSLog(@"SSLSetPeerDomainName(): %d", result);
	
	// Open keychain.
	result = SecKeychainCopyDefault(&keychain);// NSLog(@"SecKeychainOpen(): %d", result);
	
	// Create certificate.
	NSData *certificateData = [NSData dataWithContentsOfFile:self.certificate];
	CSSM_DATA data;
	data.Data = (uint8 *)[certificateData bytes];
	data.Length = [certificateData length];
	result = SecCertificateCreateFromData(&data, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certificate);// NSLog(@"SecCertificateCreateFromData(): %d", result);
	
	// Create identity.
	result = SecIdentityCreateWithCertificate(keychain, certificate, &identity);// NSLog(@"SecIdentityCreateWithCertificate(): %d", result);
	
	// Set client certificate.
	CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&identity, 1, NULL);
	result = SSLSetCertificate(context, certificates);
    // NSLog(@"SSLSetCertificate(): %d", result);
	CFRelease(certificates);
	
	// Perform SSL handshake.
	do {
		result = SSLHandshake(context);
        // NSLog(@"SSLHandshake(): %d", result);
	} while(result == errSSLWouldBlock);
	
}

- (void)disconnect {
	
	if(self.certificate == nil) {
		return;
	}
	
	// Define result variable.
	OSStatus result;
	
	// Close SSL session.
	result = SSLClose(context);
    // NSLog(@"SSLClose(): %d", result);
	
	// Release identity.
	CFRelease(identity);
	
	// Release certificate.
	CFRelease(certificate);
	
	// Release keychain.
	CFRelease(keychain);
	
	// Close connection to server.
	close((int)socket);
	
	// Delete SSL context.
	result = SSLDisposeContext(context);// NSLog(@"SSLDisposeContext(): %d", result);
	
}

#pragma mark - IBAction

- (IBAction)push:(id)sender {
	
	if(self.certificate == nil) {
		return;
	}
	
	// Validate input.
	if(self.deviceToken == nil || self.payload == nil) {
		return;
	}

	// Convert string into device token data.
	NSMutableData *deviceToken = [NSMutableData data];
	unsigned value;
	NSScanner *scanner = [NSScanner scannerWithString:self.deviceToken];
	while(![scanner isAtEnd]) {
		[scanner scanHexInt:&value];
		value = htonl(value);
		[deviceToken appendBytes:&value length:sizeof(value)];
	}
	
	// Create C input variables.
	char *deviceTokenBinary = (char *)[deviceToken bytes];
	char *payloadBinary = (char *)[self.payload UTF8String];
	size_t payloadLength = strlen(payloadBinary);
	
	// Define some variables.
	uint8_t command = 0;
	char message[293];
	char *pointer = message;
	uint16_t networkTokenLength = htons(32);
	uint16_t networkPayloadLength = htons(payloadLength);
	
	// Compose message.
	memcpy(pointer, &command, sizeof(uint8_t));
	pointer += sizeof(uint8_t);
	memcpy(pointer, &networkTokenLength, sizeof(uint16_t));
	pointer += sizeof(uint16_t);
	memcpy(pointer, deviceTokenBinary, 32);
	pointer += 32;
	memcpy(pointer, &networkPayloadLength, sizeof(uint16_t));
	pointer += sizeof(uint16_t);
	memcpy(pointer, payloadBinary, payloadLength);
	pointer += payloadLength;
	
	// Send message over SSL.
	size_t processed = 0;
	OSStatus result = SSLWrite(context, &message, (pointer - message), &processed);// NSLog(@"SSLWrite(): %d %d", result, processed);
	
}

@end
