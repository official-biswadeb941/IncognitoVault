const _0x2181c6=_0x1c50;function _0x1c50(_0x5bb11e,_0x33dca6){const _0x117305=_0x1173();return _0x1c50=function(_0x1c5000,_0x130550){_0x1c5000=_0x1c5000-0x1ea;let _0x143459=_0x117305[_0x1c5000];return _0x143459;},_0x1c50(_0x5bb11e,_0x33dca6);}function _0x1173(){const _0x666353=['type','form','11008090CzvuPj','createElement','23145JNDFAG','click','sign-up-mode','addEventListener','1144AafniO','hidden','add','querySelector','1486461GBzHbL','996816MmEStf','sign-in-btn','9DCnotC','3514OysEDm','getElementById','3346902kDuaVI','307621DPJInu','classList','csrf_token','querySelectorAll','setAttribute','input','288ZloBTm'];_0x1173=function(){return _0x666353;};return _0x1173();}(function(_0x32a2a6,_0x9e09c6){const _0x3bc21f=_0x1c50,_0x510ee9=_0x32a2a6();while(!![]){try{const _0x3b551f=parseInt(_0x3bc21f(0x1ec))/0x1+parseInt(_0x3bc21f(0x200))/0x2+parseInt(_0x3bc21f(0x1ff))/0x3+-parseInt(_0x3bc21f(0x1f2))/0x4*(parseInt(_0x3bc21f(0x1f7))/0x5)+parseInt(_0x3bc21f(0x1eb))/0x6+-parseInt(_0x3bc21f(0x203))/0x7*(parseInt(_0x3bc21f(0x1fb))/0x8)+parseInt(_0x3bc21f(0x202))/0x9*(-parseInt(_0x3bc21f(0x1f5))/0xa);if(_0x3b551f===_0x9e09c6)break;else _0x510ee9['push'](_0x510ee9['shift']());}catch(_0x1ca1dc){_0x510ee9['push'](_0x510ee9['shift']());}}}(_0x1173,0x564aa),document[_0x2181c6(0x1fa)]('DOMContentLoaded',function(){const _0x1da43a=_0x2181c6,_0x4e0cbf=document[_0x1da43a(0x1ea)]('sign-up-btn'),_0x5d4414=document[_0x1da43a(0x1ea)](_0x1da43a(0x201)),_0x1b2e0e=document[_0x1da43a(0x1fe)]('.container');_0x4e0cbf[_0x1da43a(0x1fa)]('click',()=>{const _0x5915a8=_0x1da43a;_0x1b2e0e[_0x5915a8(0x1ed)][_0x5915a8(0x1fd)](_0x5915a8(0x1f9));}),_0x5d4414[_0x1da43a(0x1fa)](_0x1da43a(0x1f8),()=>{const _0x379ad2=_0x1da43a;_0x1b2e0e[_0x379ad2(0x1ed)]['remove'](_0x379ad2(0x1f9));});}));const csrfToken=document[_0x2181c6(0x1fe)]('meta[name=\x22csrf-token\x22]')['getAttribute']('content'),forms=document[_0x2181c6(0x1ef)](_0x2181c6(0x1f4));forms['forEach'](_0xfa671=>{const _0x1f2a1d=_0x2181c6,_0x41f4ac=document[_0x1f2a1d(0x1f6)](_0x1f2a1d(0x1f1));_0x41f4ac[_0x1f2a1d(0x1f0)](_0x1f2a1d(0x1f3),_0x1f2a1d(0x1fc)),_0x41f4ac[_0x1f2a1d(0x1f0)]('name',_0x1f2a1d(0x1ee)),_0x41f4ac[_0x1f2a1d(0x1f0)]('value',csrfToken),_0xfa671['appendChild'](_0x41f4ac);});

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

