document.addEventListener('DOMContentLoaded', function() {
    const signInBtn = document.getElementById('sign-in-btn');
    const container = document.querySelector('.container');

    if (signInBtn && container) {
        signInBtn.addEventListener('click', () => {
            container.classList.remove('sign-up-mode');
        });
    }

    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        const input = document.createElement('input');
        input.setAttribute('type', 'hidden');
        input.setAttribute('name', 'csrf_token');
        input.setAttribute('value', csrfToken);
        form.appendChild(input);
    });
});



//To keep the login button disabled until the user fills out the form.
document.addEventListener('DOMContentLoaded', function() {
  const loginButton = document.getElementById('loginButton');
  const fields = document.querySelectorAll('#loginForm input[type="text"], #loginForm input[type="password"], #loginForm select');

  function checkFields() {
    let allFilled = true;

    fields.forEach(field => {
      if (field.type === 'select-one') {
        if (field.value === "" || field.value === null) {
          allFilled = false;
        }
      } else {
        if (field.value.trim() === "") {
          allFilled = false;
        }
      }
    });

    loginButton.disabled = !allFilled;
    loginButton.classList.toggle('btn-primary', allFilled);
    loginButton.classList.toggle('btn-secondary', !allFilled);
  }

  fields.forEach(field => {
    field.addEventListener('input', checkFields);
  });
  checkFields();
});

document.getElementById('loginForm').addEventListener('submit', function(event) {
  event.preventDefault(); // Prevent form submission to show loader for testing
  var loginButton = document.getElementById('loginButton');
  var loaderContainer = document.getElementById('loader-container');
  var loaderBackground = document.getElementById('loader-background');

  // Show loader and background, disable button
  loaderBackground.style.display = 'block'; // Show background
  loaderContainer.style.display = 'block'; // Show loader and text
  loginButton.value = 'Logging in...'; // Change button text
  loginButton.classList.add('loading'); // Add loading class to disable button
  loginButton.disabled = true;

  // Simulate form submission delay for demonstration purposes
  setTimeout(function() {
    document.getElementById('loginForm').submit(); // Uncomment for real form submission
  }, 3000); // 3 second delay for testing
});

function loadCaptcha() {
  fetch('/api/captcha')
      .then(response => {
          if (!response.ok) {
              throw new Error('Network response was not ok');
          }
          return response.blob(); 
      })
      .then(blob => {
          const imgUrl = URL.createObjectURL(blob);
          document.getElementById('captcha-image').src = imgUrl;
      })
      .catch(error => {
          console.error('There has been a problem with your fetch operation:', error);
      });
}
function reloadCaptcha() {
  loadCaptcha();
}
window.onload = loadCaptcha;

document.addEventListener('DOMContentLoaded', function() {
  const roleDropdown = document.getElementById('role');
  const body = document.body;
  const loginForm = document.querySelector('.login-form');
  const formControls = document.querySelectorAll('.form-control');
  const loader = document.getElementById('loader-background');

  roleDropdown.addEventListener('change', function() {
    // Remove any existing theme class from body, login form, form controls, and loader
    body.classList.remove('super-admin-theme', 'admin-theme', 'user-theme');
    loginForm.classList.remove('super-admin-theme', 'admin-theme', 'user-theme');
    formControls.forEach(function(formControl) {
      formControl.classList.remove('super-admin-theme', 'admin-theme', 'user-theme');
    });
    loader.classList.remove('super-admin-theme', 'admin-theme', 'user-theme');

    // Apply the selected theme based on the role
    switch (this.value) {
      case 'super_admin':
        body.classList.add('super-admin-theme');
        loginForm.classList.add('super-admin-theme');
        formControls.forEach(function(formControl) {
          formControl.classList.add('super-admin-theme');
        });
        loader.classList.add('super-admin-theme');
        break;
      case 'admin':
        body.classList.add('admin-theme');
        loginForm.classList.add('admin-theme');
        formControls.forEach(function(formControl) {
          formControl.classList.add('admin-theme');
        });
        loader.classList.add('admin-theme');
        break;
      case 'user':
        body.classList.add('user-theme');
        loginForm.classList.add('user-theme');
        formControls.forEach(function(formControl) {
          formControl.classList.add('user-theme');
        });
        loader.classList.add('user-theme');
        break;
      default:
        break;
    }
  });
});


