//go:build desktop && darwin

package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// setDockIcon sets the icon of the running application (the Dock tile, the app switcher). Inside IceVault.app it is the icon the system draws for the
// bundle (the same as in Finder); a program started outside a bundle gets the embedded artwork, rounded the way the system rounds an application icon
// (the 824-point body of the 1024 grid). The bytes are copied before the call returns; the work runs on the main thread.
static void setDockIcon(const void *png, int n) {
	NSData *data = [NSData dataWithBytes:png length:(NSUInteger)n];
	dispatch_async(dispatch_get_main_queue(), ^{
		@autoreleasepool {
			NSImage *img = nil;
			NSString *bundle = [[NSBundle mainBundle] bundlePath];
			if ([[bundle pathExtension] caseInsensitiveCompare:@"app"] == NSOrderedSame) {
				img = [[NSWorkspace sharedWorkspace] iconForFile:bundle];
			} else {
				NSImage *art = [[NSImage alloc] initWithData:data];
				if (art != nil) {
					img = [NSImage imageWithSize:NSMakeSize(1024, 1024) flipped:NO drawingHandler:^BOOL(NSRect dst) {
						NSRect body = NSMakeRect(100, 100, 824, 824);
						[[NSBezierPath bezierPathWithRoundedRect:body xRadius:185.4 yRadius:185.4] addClip];
						[art drawInRect:body fromRect:NSZeroRect operation:NSCompositingOperationSourceOver fraction:1.0];
						return YES;
					}];
				}
			}
			if (img != nil) {
				[NSApp setApplicationIconImage:img];
			}
		}
	});
}
*/
import "C"

import (
	_ "embed"
	"unsafe"
)

// appIcon is the artwork of the application icon (full bleed, 1024 px): the Dock icon of a window program that runs outside IceVault.app.
//
//go:embed app/icon-1024.png
var appIcon []byte

// setDockIcon makes the Dock show the application's icon however the window was started: through LaunchServices (Finder, open), by exec of the program
// inside the bundle from a terminal (icevault ui, mise run icevault-window), or as a program outside any bundle (which macOS shows with the generic
// "exec" icon). Called once the application object exists (OnStartup).
func setDockIcon() {
	C.setDockIcon(unsafe.Pointer(&appIcon[0]), C.int(len(appIcon)))
}
