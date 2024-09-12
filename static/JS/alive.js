const _0x2308e3=_0x4a54;function _0x7a0c(){const _0x4791d2=['10459246EiegIv','5HuUaZT','3114mGqOlq','content','11608kQbfLv','37231370FpgdJc','12MeNXVZ','68646aorQrb','2648gHaSTf','1203ABhmnQ','49PbccAX','ready','POST','68342rXPoBU','meta[name=\x22csrf-token\x22]','ajax','/keep_alive','1185450GnUbdA'];_0x7a0c=function(){return _0x4791d2;};return _0x7a0c();}function _0x4a54(_0x164dc,_0x3d611d){const _0x7a0cfd=_0x7a0c();return _0x4a54=function(_0x4a5441,_0x4db984){_0x4a5441=_0x4a5441-0x1df;let _0x120398=_0x7a0cfd[_0x4a5441];return _0x120398;},_0x4a54(_0x164dc,_0x3d611d);}(function(_0x3e105c,_0x3d2f82){const _0x67952=_0x4a54,_0x5bd6d0=_0x3e105c();while(!![]){try{const _0x5ae0cc=parseInt(_0x67952(0x1e2))/0x1*(parseInt(_0x67952(0x1e5))/0x2)+parseInt(_0x67952(0x1e1))/0x3*(parseInt(_0x67952(0x1ee))/0x4)+-parseInt(_0x67952(0x1eb))/0x5*(-parseInt(_0x67952(0x1df))/0x6)+parseInt(_0x67952(0x1ea))/0x7+-parseInt(_0x67952(0x1e0))/0x8*(parseInt(_0x67952(0x1ec))/0x9)+parseInt(_0x67952(0x1e9))/0xa+parseInt(_0x67952(0x1ef))/0xb*(-parseInt(_0x67952(0x1f0))/0xc);if(_0x5ae0cc===_0x3d2f82)break;else _0x5bd6d0['push'](_0x5bd6d0['shift']());}catch(_0x6e72e){_0x5bd6d0['push'](_0x5bd6d0['shift']());}}}(_0x7a0c,0xeb1e9),$(document)[_0x2308e3(0x1e3)](function(){const _0x46bf70=()=>{const _0x3e64fa=_0x4a54;$[_0x3e64fa(0x1e7)]({'url':_0x3e64fa(0x1e8),'type':_0x3e64fa(0x1e4),'headers':{'X-CSRFToken':$(_0x3e64fa(0x1e6))['attr'](_0x3e64fa(0x1ed))},'success':_0x13ea5e=>{},'error':(_0x5405f0,_0x1c93b5,_0xa33774)=>{}});},_0x9e3acc=0x1*0x3c*0x3e8;setInterval(_0x46bf70,_0x9e3acc),_0x46bf70();}));


let totalDuration = 75 * 1000; // Total duration (1 minute 15 seconds) in milliseconds
let warningDuration = 15 * 1000; // Warning popup duration (15 seconds) in milliseconds
let timeoutId, warningId, countdownId, isPopupShown = false;

function resetTimers() {
    clearTimeout(timeoutId);
    clearTimeout(warningId);
    clearInterval(countdownId);

    timeoutId = setTimeout(logoutUser, totalDuration);
    warningId = setTimeout(showWarningPopup, totalDuration - warningDuration);
}

function showWarningPopup() {
    if (isPopupShown) return; // Prevent multiple popups
    isPopupShown = true;

    // Create and show warning popup
    const popup = document.createElement('div');
    popup.id = 'warning-popup';
    popup.style.position = 'fixed';
    popup.style.top = '50%';
    popup.style.left = '50%';
    popup.style.transform = 'translate(-50%, -50%)'; // Center the popup
    popup.style.backgroundColor = '#f8d7da';
    popup.style.color = '#721c24';
    popup.style.border = '1px solid #f5c6cb';
    popup.style.padding = '20px';
    popup.style.zIndex = '9999';
    popup.style.borderRadius = '8px';
    popup.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
    popup.style.textAlign = 'center'; // Center text
    popup.style.fontSize = '16px'; // Font size for better readability

    const message = document.createElement('div');
    message.id = 'warning-message';
    popup.appendChild(message);

    const closeButton = document.createElement('button');
    closeButton.innerText = 'Close';
    closeButton.onclick = extendSession;
    closeButton.style.marginTop = '10px'; // Space between message and button
    closeButton.style.backgroundColor = '#721c24';
    closeButton.style.color = '#fff';
    closeButton.style.border = 'none';
    closeButton.style.borderRadius = '4px';
    closeButton.style.padding = '8px 16px';
    closeButton.style.cursor = 'pointer';
    closeButton.style.fontSize = '14px';
    popup.appendChild(closeButton);

    document.body.appendChild(popup);

    let remainingTime = warningDuration / 1000;
    countdownId = setInterval(() => {
        remainingTime--;
        message.innerHTML = `You will be logged out in ${remainingTime}s.`;
        if (remainingTime <= 0) {
            clearInterval(countdownId);
            logoutUser();
        }
    }, 1000);
}

function extendSession() {
    resetTimers();
    const popup = document.getElementById('warning-popup');
    if (popup) {
        popup.remove();
    }
    isPopupShown = false;
}

function logoutUser() {
    window.location.href = '/logout'; // Redirect to logout route
}

function handleUserActivity() {
    resetTimers();

    // Check if the popup is shown and remove it
    if (isPopupShown) {
        extendSession(); // Calls extendSession which resets the popup state and timers
    }
}

function handleVisibilityChange() {
    if (document.visibilityState === 'visible') {
        resetTimers();
    }
}

// Event listeners
document.addEventListener('mousemove', handleUserActivity);
document.addEventListener('keydown', handleUserActivity);
document.addEventListener('click', handleUserActivity);
document.addEventListener('visibilitychange', handleVisibilityChange);

// Start the timer when the page loads
resetTimers();

