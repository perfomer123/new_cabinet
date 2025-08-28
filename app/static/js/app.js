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

// Подсветка ссылок в админ-сайдбаре
(function(){
  document.addEventListener(DOMContentLoaded, function(){
    var path = location.pathname.replace(/\/$/, );
    document.querySelectorAll(.admin-sidebar a.nav-link, .admin-sidebar-nav .nav-link, .admin-sidebar-nav .list-group-item).forEach(function(a){
      var href=(a.getAttribute(href)||).replace(/\/$/, );
      if(href && (href===path || (href!==/ && path.startsWith(href)))){ a.classList.add(active); }
    });
  });
})();

// UI helpers: overlay + toasts (Bootstrap 5)
(function(){
  function ensureUiShell(){
    var body = document.body;
    if (!document.getElementById('loadingOverlay')){
      var ov = document.createElement('div');
      ov.id = 'loadingOverlay';
      ov.className = 'loading-overlay';
      ov.style.display = 'none';
      ov.innerHTML = '<div class=spinner-border text-light role=status><span class=visually-hidden>Загрузка...</span></div><div class=loading-message mt-3 text-light>Загрузка...</div>';
      body.appendChild(ov);
    }
    if (!document.getElementById('toastRoot')){
      var wrap = document.createElement('div');
      wrap.id = 'toastRoot';
      wrap.className = 'position-fixed top-0 end-0 p-3';
      wrap.style.zIndex = 1105;
      wrap.innerHTML = '<div id=toastContainer class=toast-container></div>';
      body.appendChild(wrap);
    }
  }

  document.addEventListener('DOMContentLoaded', function(){
    ensureUiShell();
    if (window.AppUtils){
      AppUtils.showLoading = function(message){
        ensureUiShell();
        var ov = document.getElementById('loadingOverlay');
        var msg = ov.querySelector('.loading-message');
        if (msg && message) msg.textContent = message;
        ov.style.display = 'flex';
      };
      AppUtils.hideLoading = function(){
        var ov = document.getElementById('loadingOverlay');
        if (ov) ov.style.display = 'none';
      };
      AppUtils.showNotification = function(message, type, duration){
        ensureUiShell();
        var root = document.getElementById('toastContainer');
        var color = (type==='success')?'bg-success':(type==='danger')?'bg-danger':(type==='warning')?'bg-warning text-dark':'bg-primary';
        var el = document.createElement('div');
        el.className = 'toast align-items-center text-white border-0 '+color;
        el.setAttribute('role','alert');
        el.setAttribute('aria-live','assertive');
        el.setAttribute('aria-atomic','true');
        el.innerHTML = '<div class=d-flex><div class=toast-body>'+message+'</div><button type=button class=btn-close btn-close-white me-2 m-auto data-bs-dismiss=toast aria-label=Close></button></div>';
        root.appendChild(el);
        var toast = new bootstrap.Toast(el, { delay: duration || 4000 });
        toast.show();
        el.addEventListener('hidden.bs.toast', function(){ el.remove(); });
      };
    }
  });
})();

// UI helpers: overlay + toasts (Bootstrap 5)
(function(){
  function ensureUiShell(){
    var body = document.body;
    if (!document.getElementById('loadingOverlay')){
      var ov = document.createElement('div');
      ov.id = 'loadingOverlay';
      ov.className = 'loading-overlay';
      ov.style.display = 'none';
      ov.innerHTML = '<div class=spinner-border text-light role=status><span class=visually-hidden>Загрузка...</span></div><div class=loading-message mt-3 text-light>Загрузка...</div>';
      body.appendChild(ov);
    }
    if (!document.getElementById('toastRoot')){
      var wrap = document.createElement('div');
      wrap.id = 'toastRoot';
      wrap.className = 'position-fixed top-0 end-0 p-3';
      wrap.style.zIndex = 1105;
      wrap.innerHTML = '<div id=toastContainer class=toast-container></div>';
      body.appendChild(wrap);
    }
  }

  document.addEventListener('DOMContentLoaded', function(){
    ensureUiShell();
    if (window.AppUtils){
      AppUtils.showLoading = function(message){
        ensureUiShell();
        var ov = document.getElementById('loadingOverlay');
        var msg = ov.querySelector('.loading-message');
        if (msg && message) msg.textContent = message;
        ov.style.display = 'flex';
      };
      AppUtils.hideLoading = function(){
        var ov = document.getElementById('loadingOverlay');
        if (ov) ov.style.display = 'none';
      };
      AppUtils.showNotification = function(message, type, duration){
        ensureUiShell();
        var root = document.getElementById('toastContainer');
        var color = (type==='success')?'bg-success':(type==='danger')?'bg-danger':(type==='warning')?'bg-warning text-dark':'bg-primary';
        var el = document.createElement('div');
        el.className = 'toast align-items-center text-white border-0 '+color;
        el.setAttribute('role','alert');
        el.setAttribute('aria-live','assertive');
        el.setAttribute('aria-atomic','true');
        el.innerHTML = '<div class=d-flex><div class=toast-body>'+message+'</div><button type=button class=btn-close btn-close-white me-2 m-auto data-bs-dismiss=toast aria-label=Close></button></div>';
        root.appendChild(el);
        var toast = new bootstrap.Toast(el, { delay: duration || 4000 });
        toast.show();
        el.addEventListener('hidden.bs.toast', function(){ el.remove(); });
      };
    }
  });
})();

// Override fetchData to avoid object spread (legacy-safe)
(function(){
  document.addEventListener('DOMContentLoaded', function(){
    if (window.AppUtils){
      AppUtils.fetchData = async function(url, options){
        try{
          this.showLoading();
          var opts = Object.assign({}, options || {});
          var headers = Object.assign({'X-Requested-With': 'XMLHttpRequest'}, (opts.headers||{}));
          opts.headers = headers;
          var response = await fetch(url, opts);
          if(!response.ok) throw new Error('HTTP '+response.status+': '+response.statusText);
          var data = await response.json();
          if (data && data.error) throw new Error(data.error);
          return data;
        } catch(err){
          console.error('Fetch error:', err);
          this.showNotification(err.message || 'Ошибка сети', 'danger');
          throw err;
        } finally {
          this.hideLoading();
        }
      }
    }
  });
})();
