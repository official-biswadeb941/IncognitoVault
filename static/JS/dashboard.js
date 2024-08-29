document.addEventListener("DOMContentLoaded", function(event) {
const showNavbar = (toggleId, navId, bodyId, headerId) =>{
const toggle = document.getElementById(toggleId),
nav = document.getElementById(navId),
bodypd = document.getElementById(bodyId),
headerpd = document.getElementById(headerId)

if(toggle && nav && bodypd && headerpd){
toggle.addEventListener('click', ()=>{
nav.classList.toggle('show')
toggle.classList.toggle('bx-x')
bodypd.classList.toggle('body-pd')
headerpd.classList.toggle('body-pd')
})
}
}

showNavbar('header-toggle','nav-bar','body-pd','header')
const linkColor = document.querySelectorAll('.nav_link')
function colorLink(){
if(linkColor){
linkColor.forEach(l=> l.classList.remove('active'))
this.classList.add('active')
}
}
linkColor.forEach(l=> l.addEventListener('click', colorLink))

});

//Function for putting csrf token in header.
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
const forms = document.querySelectorAll('form');
forms.forEach(form => {
const csrfInput = document.createElement('input');
csrfInput.setAttribute('type', 'hidden');
csrfInput.setAttribute('name', 'csrf_token');
csrfInput.setAttribute('value', csrfToken);
form.appendChild(csrfInput);
});

//Preloader & Loader
document.addEventListener("DOMContentLoaded", function() {
    const loader = document.getElementById('loader');
    window.addEventListener('load', function() {
        loader.classList.add('hidden');
    });
    const loginForm = document.querySelector('form'); 
        if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            loader.classList.remove('hidden'); 
            event.preventDefault();
            setTimeout(function() {
                loginForm.submit();
            }, 100); 
        });
    }
});


// Function to show notifications
function showNotification(message, type) {
  var notification = document.getElementById('notification');
  notification.className = 'notification ' + type;
  notification.textContent = message;
  notification.style.display = 'block';
  // Add notification to history
  addNotificationToHistory(message, type);
  // Hide notification after 5 seconds
  setTimeout(function () {
    notification.style.display = 'none';
  }, 5000);
}

// Function to add notifications to history
function addNotificationToHistory(message, type) {
  var notificationHistoryList = document.getElementById('notification-history-list');
  var newNotificationItem = document.createElement('div');
  newNotificationItem.className = 'notification-item ' + type;
  newNotificationItem.textContent = message;
  notificationHistoryList.appendChild(newNotificationItem);
}
// Function to save notifications to localStorage
function saveNotification(message, type) {
  var notifications = JSON.parse(localStorage.getItem('notifications')) || [];
  notifications.push({ message: message, type: type });
  localStorage.setItem('notifications', JSON.stringify(notifications));
}
// Function to load notifications from localStorage
function loadNotifications() {
  var notifications = JSON.parse(localStorage.getItem('notifications')) || [];
  notifications.forEach(function (notification) {
    addNotificationToHistory(notification.message, notification.type);
  });
}
// Demo: Trigger a notification and save it
window.onload = function () {
  var demoMessage = 'This is a persistent demo notification!';
  var demoType = 'info';
  // Check if the demo notification already exists
  var notifications = JSON.parse(localStorage.getItem('notifications')) || [];
  var demoExists = notifications.some(notification => notification.message === demoMessage);
  if (!demoExists) {
    showNotification(demoMessage, demoType);
    saveNotification(demoMessage, demoType);
  }
  // Load existing notifications
  loadNotifications();
};
