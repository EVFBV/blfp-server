let dlDataLoaded = false;

fetch('/api/settings/public')
  .then((response) => response.ok ? response.json() : Promise.reject())
  .then((settings) => {
    if (settings.site_title) {
      document.title = settings.site_title;
      document.getElementById('site-title').textContent = settings.site_title;
    }
    if (settings.site_desc) document.getElementById('site-desc').textContent = settings.site_desc;
    fillDownloadOverlay(settings);
  })
  .catch(() => {});

function fillDownloadOverlay(settings) {
  if (settings.site_title) document.getElementById('dl-title').textContent = settings.site_title;
  if (settings.latest_version) {
    document.getElementById('dl-ver').textContent = '最新版本 v' + settings.latest_version + ' · 全平台客户端下载';
  }
  const map = {
    'dl-win': settings.downloads && settings.downloads.win,
    'dl-linux': settings.downloads && settings.downloads.linux,
    'dl-macos': settings.downloads && settings.downloads.macos,
  };
  for (const [id, url] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (url) el.href = url; else el.classList.add('disabled');
  }
  dlDataLoaded = true;
}

function openDownloadOverlay() {
  if (!dlDataLoaded) {
    fetch('/api/settings/public')
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then(fillDownloadOverlay)
      .catch(() => {});
  }
  document.getElementById('dl-overlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeDownloadOverlay() {
  document.getElementById('dl-overlay').classList.remove('open');
  document.body.style.overflow = '';
}