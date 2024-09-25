document.addEventListener("DOMContentLoaded", function(event) {
  // Navbar toggle function
  const showNavbar = (toggleId, navId, bodyId, headerId) => {
    const toggle = document.getElementById(toggleId),
      nav = document.getElementById(navId),
      bodypd = document.getElementById(bodyId),
      headerpd = document.getElementById(headerId);

    if (toggle && nav && bodypd && headerpd) {
      toggle.addEventListener('click', () => {
        nav.classList.toggle('show');
        toggle.classList.toggle('bx-x');
        bodypd.classList.toggle('body-pd');
        headerpd.classList.toggle('body-pd');
      });
    }
  };

  showNavbar('header-toggle', 'nav-bar', 'body-pd', 'header');

  // Navbar link active state function
  const linkColor = document.querySelectorAll('.nav_link');
  function colorLink() {
    if (linkColor) {
      linkColor.forEach(l => l.classList.remove('active'));
      this.classList.add('active');
    }
  }
  linkColor.forEach(l => l.addEventListener('click', colorLink));

  // Toggle email configuration sections function
  function toggleEmailOption(option) {
    const smtpConfig = document.getElementById('smtp-config');
    const apiConfig = document.getElementById('api-config');
    
    if (option === 'smtp') {
      if (smtpOption.checked) {
        smtpConfig.style.display = 'block';
        apiConfig.style.display = 'none';
        apiOption.checked = false;
      } else {
        smtpConfig.style.display = 'none';
      }
    } else if (option === 'api') {
      if (apiOption.checked) {
        apiConfig.style.display = 'block';
        smtpConfig.style.display = 'none';
        smtpOption.checked = false;
      } else {
        apiConfig.style.display = 'none';
      }
    }
  }

  const smtpOption = document.getElementById('smtp-option');
  const apiOption = document.getElementById('api-option');

  smtpOption.addEventListener('change', function() {
    if (smtpOption.checked) {
      toggleEmailOption('smtp');
    }
  });

  apiOption.addEventListener('change', function() {
    if (apiOption.checked) {
      toggleEmailOption('api');
    }
  });

  // Handle active class based on current URL
  const currentPath = window.location.pathname;
  const navLinks = [
    { path: '/Dashboard', elementId: 'dashboard-link' },
    { path: '/Form', elementId: 'form-link' },
    { path: '/Database', elementId: 'database-link' },
    { path: '/Logs', elementId: 'logs-link' },
    { path: '/Settings', elementId: 'settings-link' },
  ];

  navLinks.forEach(link => {
    const navElement = document.getElementById(link.elementId);
    if (currentPath === link.path) {
      navElement.classList.add('active');
    } else {
      navElement.classList.remove('active');
    }
  });

  // Logs section
  function addLogEntry(log) {
    const tableBody = document.getElementById('logs-table-body');
    const newRow = document.createElement('tr');

    newRow.innerHTML = `
      <th scope="row">${log.id}</th>
      <td>${log.userName}</td>
      <td>${log.ipAddress}</td>
      <td>${log.dateTime}</td>
      <td>${log.criticality}</td>
      <td>${log.userAction}</td>
    `;

    tableBody.appendChild(newRow);
  }

  // Example log entry
  addLogEntry({
    id: 3,
    userName: 'Alice Brown',
    ipAddress: '192.168.1.3',
    dateTime: '2024-08-26 12:40:30',
    criticality: 'Low',
    userAction: 'Database query'
  });

  // Future Function Placeholder
  // Add new functions below this comment
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

const toggler = document.querySelector('.navbar-toggler');
const dots = document.getElementById('three-dots');

// Initially set the dots to vertical
dots.classList.add('vertical');

toggler.addEventListener('click', function() {
    if (dots.classList.contains('vertical')) {
        dots.classList.remove('vertical');
        dots.classList.add('horizontal');
    } else {
        dots.classList.remove('horizontal');
        dots.classList.add('vertical');
    }
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

$(document).ready(function(){
  // Check if dropdown is working
  $('#dropdownMenuButton').on('click', function(){
    console.log('Dropdown button clicked');
  });
});

//Dynamic Registration Form
let fieldCount = 0;

function addField() {
  fieldCount++;
  const dynamicFields = document.getElementById('dynamic-fields');
  const fieldHTML = `
    <div class="mb-3" id="field-${fieldCount}">
      <label for="custom-field-${fieldCount}" class="form-label">Field Name</label>
      <input type="text" class="form-control" id="custom-field-${fieldCount}" name="custom-field-${fieldCount}" required>
      <!-- Dustbin icon for delete -->
      <button type="button" class="btn btn-danger mt-2" onclick="removeField(${fieldCount})">
        <i class="fas fa-trash-alt"></i> Remove Field
      </button>
    </div>
  `;
  dynamicFields.insertAdjacentHTML('beforeend', fieldHTML);
}

function removeField(id) {
  const field = document.getElementById(`field-${id}`);
  field.remove();
}