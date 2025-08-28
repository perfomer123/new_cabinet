// SOVA Cabinet — утилиты и мелкие улучшения UI
(function(){
  document.addEventListener('DOMContentLoaded', function(){
    // Подсветка активных пунктов меню по URL
    var path = location.pathname.replace(/\/$/, '');
    document.querySelectorAll('.navbar .nav-link').forEach(function(a){
      try { 
        var href = (a.getAttribute('href')||'').replace(/\/$/, '');
        if (href && (href === path || (href !== '/' && path.startsWith(href)))) {
          a.classList.add('active');
        }
      } catch(e){}
    });
  });
})();
