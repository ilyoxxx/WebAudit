document.querySelectorAll('[data-origin]').forEach(function (el) {
      var c = el.querySelector('code');
      c.textContent = c.textContent.split('ORIGIN').join(location.origin);
    });
