'use strict';
(function () {
    const fallbacks = new Set(['/tools/vendor/pdf-lib.min.js?v=0f9a5cad07941f08', '/tools/vendor/jszip.min.js?v=acc7e41455a80765']
        .map(url => new URL(url, location.href).pathname));
    document.addEventListener('error', event => {
        const node = event.target;
        if (node?.tagName === 'SCRIPT' && node.hasAttribute('data-cdn-fallback')) {
            const fallback = new URL(node.getAttribute('data-cdn-fallback'), location.href);
            if (fallback.origin !== location.origin || !fallbacks.has(fallback.pathname)) return;
            node.removeAttribute('data-cdn-fallback');
            node.removeAttribute('integrity');
            node.removeAttribute('crossorigin');
            node.src = fallback.href;
        } else if (node?.tagName === 'IMG') {
            const action = node.getAttribute('data-image-fallback');
            if (action === 'logo') {
                node.style.display = 'none';
                node.parentElement?.classList.add('img-failed');
            } else if (action === 'parent' && node.parentElement) {
                node.parentElement.style.display = 'none';
            }
        }
    }, true);
})();
