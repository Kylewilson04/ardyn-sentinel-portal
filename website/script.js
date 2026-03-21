// Scroll fade-in animations
document.addEventListener('DOMContentLoaded', () => {
    // Add fade-in class to animatable elements
    const selectors = '.step, .card, .pricing-card, .stat, .arch-node, .section-narrow, h2, .hero-headline, .hero-sub, .hero-actions';
    document.querySelectorAll(selectors).forEach(el => el.classList.add('fade-in'));

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('.fade-in').forEach(el => observer.observe(el));

    // Mobile nav toggle
    const toggle = document.querySelector('.nav-toggle');
    const links = document.querySelector('.nav-links');
    if (toggle && links) {
        toggle.addEventListener('click', () => links.classList.toggle('open'));
        links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => links.classList.remove('open')));
    }

    // Waitlist form
    const form = document.getElementById('waitlist-form');
    const msg = document.getElementById('waitlist-msg');
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = form.querySelector('input[type="email"]');
            const email = input.value.trim();
            if (!email) return;
            const btn = form.querySelector('button');
            btn.disabled = true;
            btn.textContent = 'Joining...';
            try {
                const res = await fetch('/api/waitlist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                const data = await res.json();
                if (data.ok) {
                    msg.textContent = data.message;
                    msg.style.color = '#059669';
                    input.value = '';
                } else {
                    msg.textContent = data.error || 'Something went wrong.';
                    msg.style.color = '#dc2626';
                }
            } catch {
                msg.textContent = 'Network error — please try again.';
                msg.style.color = '#dc2626';
            }
            btn.disabled = false;
            btn.textContent = 'Join Waitlist';
        });
    }
});
