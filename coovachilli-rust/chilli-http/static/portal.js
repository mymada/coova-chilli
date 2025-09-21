function login(form) {
    // Open a blank popup. The form submission will be targeted to this popup.
    const popup = window.open('about:blank', 'coovachilli_popup', 'toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,width=500,height=375');
    if (popup) {
        // Set the form's target to the popup window's name
        form.target = 'coovachilli_popup';
        // Allow the form to be submitted
        return true;
    }
    // If the popup was blocked, prevent the form from submitting
    alert('A popup window is required for login. Please disable your popup blocker for this site.');
    return false;
}

function doOnLoad(res, is_popup, userurl) {
    // If this window is a popup and the login was successful...
    if (is_popup && res === 'success') {
        // ...and the window that opened it still exists...
        if (opener && !opener.closed) {
            // ...redirect the original window.
            opener.location = userurl || '/status';
        }
        // ...and close the popup.
        self.close();
    }
}
