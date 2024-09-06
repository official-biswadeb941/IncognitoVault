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

// JavaScript to handle active class switching based on current URL
document.addEventListener('DOMContentLoaded', function () {
  // Get the current pathname (e.g., "/Dashboard", "/Form")
  const currentPath = window.location.pathname;

  // List of nav links and their corresponding paths
  const navLinks = [
      { path: '/Dashboard', elementId: 'dashboard-link' },
      { path: '/Form', elementId: 'form-link' },
      { path: '/Database', elementId: 'database-link' },
      { path: '/Logs', elementId: 'logs-link' },
      { path: '/Settings', elementId: 'settings-link' },
  ];

  // Loop through each nav link to find the match and add the 'active' class
  navLinks.forEach(link => {
      const navElement = document.getElementById(link.elementId);
      if (currentPath === link.path) {
          navElement.classList.add('active');
      } else {
          navElement.classList.remove('active');
      }
  });
});

function updateDateTime() {
  const now = new Date();
  const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Asia/Kolkata', hour12: true };
  const dateOptions = { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'Asia/Kolkata' };

  const time = now.toLocaleTimeString('en-IN', timeOptions);
  const date = now.toLocaleDateString('en-IN', dateOptions);

  const dateTime = `${time}, ${date}`;
  document.getElementById('date-time').textContent = dateTime;
}

updateDateTime();
setInterval(updateDateTime, 1000); // Update date and time every second

//Footer Date 
document.getElementById('year').textContent = new Date().getFullYear();