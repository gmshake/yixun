#import <Cocoa/Cocoa.h>

#ifdef DEBUG
#define DNSLog(...) NSLog(__VA_ARGS__)
#else
#define DNSLog(...) (void)0
#endif

@interface yiXunGUI : NSObject {
    IBOutlet NSButton *mAutoConnect;
    IBOutlet NSButton *mAutoReconnect;
    IBOutlet NSButton *mAutoHide;
    IBOutlet NSTextField *mServerIP;
    IBOutlet NSTextField *mClientIP;
    IBOutlet NSTextField *mMAC;
    IBOutlet NSButton *mExit;
    IBOutlet NSButton *mLogin;
    IBOutlet NSTextField *mPassword;
    IBOutlet NSTextField *mUsername;
    IBOutlet NSTextView *mLogs;
    IBOutlet NSWindow *mMainWindow;
    //IBOutlet NSWindow * m_PrefWindow;
    IBOutlet NSApplication *mApp;
}

- (IBAction)aExit:(id)sender;
- (IBAction)aLogin:(id)sender;
- (IBAction)aSettingChanged:(id)sender;
- (void)changeUIState;
- (void)settingRestore;
- (void)settingSave;
- (void)awakeFromNib;
- (void)applicationWillTerminate:(NSNotification *)aNotification;
- (BOOL)windowShouldClose:(id)sender;
- (void)sheetDidEnd:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo;
- (void)runExternalProcess;
- (void)terminalExternalProcess;
- (void)keepalive:(NSTimer *)timer;
@end
