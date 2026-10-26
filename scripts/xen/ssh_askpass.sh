#!/bin/sh
# Password passes directly from the hidden macOS dialog to SSH's askpass pipe.
# Do not trace, log, export or save the response.
exec /usr/bin/osascript <<'APPLESCRIPT'
set response to display dialog "Enter the XCP-ng host password requested by SSH." default answer "" with title "XCP-ng Host Login" with hidden answer buttons {"Cancel", "Log In"} default button "Log In"
text returned of response
APPLESCRIPT
