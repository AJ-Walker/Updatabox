document.addEventListener('DOMContentLoaded', () => {
    (document.querySelectorAll('.notification .delete') || []).forEach(($delete) => {
      const $notification = $delete.parentNode;
  
      $delete.addEventListener('click', () => {
        $notification.parentNode.removeChild($notification);
      });
    });
  });


// var navButton = document.querySelector(".navbar-burger");
// var navMenu = document.querySelector(".navbar-menu");

// navButton.addEventListener('click', function(e){
//     navMenu.classList.toggle('is-active');
// });