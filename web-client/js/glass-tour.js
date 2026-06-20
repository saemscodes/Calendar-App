/**
 * SafeTrack Demo Tour (Glassmorphism UI)
 * 
 * ONLY executes if '?demo=1' is present in the URL.
 * Creates an elegant, glassmorphic onboarding bubble to explain the Zero-Exposure architecture.
 * This script is fully decoupled from production app logic.
 */

(function () {
  if (!window.location.search.includes('demo=1')) return;

  const style = document.createElement('style');
  style.textContent = `
    .st-tour-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.4);
      z-index: 99998;
      pointer-events: auto;
      backdrop-filter: blur(2px);
      -webkit-backdrop-filter: blur(2px);
      transition: opacity 0.3s ease;
    }
    .st-tour-bubble {
      position: fixed;
      width: 320px;
      padding: 20px;
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.15);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.3);
      box-shadow: 0 10px 40px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.4);
      z-index: 99999;
      color: #fff;
      font-family: 'SF Pro Display', 'Inter', sans-serif;
      transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      opacity: 0;
      transform: translateY(10px) scale(0.95);
    }
    .st-tour-bubble.visible {
      opacity: 1;
      transform: translateY(0) scale(1);
    }
    .st-tour-title {
      margin: 0 0 8px 0;
      font-size: 18px;
      font-weight: 700;
      text-shadow: 0 1px 2px rgba(0,0,0,0.2);
    }
    .st-tour-text {
      margin: 0 0 16px 0;
      font-size: 14px;
      line-height: 1.5;
      font-weight: 400;
      color: rgba(255,255,255,0.9);
    }
    .st-tour-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .st-tour-progress {
      font-size: 12px;
      color: rgba(255,255,255,0.6);
      font-weight: 500;
    }
    .st-tour-btn {
      background: #02B9FC;
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(2, 185, 252, 0.3);
      transition: transform 0.1s;
    }
    .st-tour-btn:active {
      transform: scale(0.95);
    }
    .st-tour-btn-outline {
      background: transparent;
      color: #fff;
      box-shadow: none;
      padding: 8px 0;
    }
    /* Highlight the target element */
    .st-tour-highlight {
      position: relative;
      z-index: 99999 !important;
      box-shadow: 0 0 0 4px rgba(2, 185, 252, 0.5) !important;
      border-radius: inherit;
      pointer-events: none;
    }
  `;
  document.head.appendChild(style);

  const steps = [
    {
      target: '.cal-search-input',
      title: 'The Decoy Interface',
      text: 'To anyone looking over your shoulder, this is just a standard iOS calendar. But this search bar is actually the Stealth Router. Type your secret PIN here to authenticate and unlock the SafeTrack network.',
      position: 'bottom'
    },
    {
      target: '.cal-add-day-btn',
      title: 'Fully Functional Ruse',
      text: 'You can actually add, edit, and save real calendar events. This ensures the app holds up to scrutiny if accessed by unauthorized parties.',
      position: 'bottom'
    },
    {
      target: '#btn-sos', /* Available only after login, we will mock it or just anchor to center */
      title: 'Silent Emergency SOS',
      text: 'Once inside, sliding the SOS button dispatches an instant silent alert via Supabase Realtime to your trusted contacts, broadcasting your live GPS location.',
      position: 'top',
      requireSafeTrack: true
    },
    {
      target: null,
      title: 'Zero-Exposure Architecture',
      text: 'We use Vercel Serverless and Supabase. No seed phrases are ever saved to the database, and memory is instantly wiped the moment the app closes or you press Panic Logout. Stay safe!',
      position: 'center'
    }
  ];

  let currentStep = 0;
  let overlay, bubble, titleEl, textEl, progressEl, nextBtn, skipBtn;
  let currentTargetEl = null;

  function initDOM() {
    overlay = document.createElement('div');
    overlay.className = 'st-tour-overlay';
    document.body.appendChild(overlay);

    bubble = document.createElement('div');
    bubble.className = 'st-tour-bubble';
    
    titleEl = document.createElement('h3');
    titleEl.className = 'st-tour-title';
    
    textEl = document.createElement('p');
    textEl.className = 'st-tour-text';
    
    const footer = document.createElement('div');
    footer.className = 'st-tour-footer';
    
    progressEl = document.createElement('div');
    progressEl.className = 'st-tour-progress';
    
    const btnGroup = document.createElement('div');
    
    skipBtn = document.createElement('button');
    skipBtn.className = 'st-tour-btn st-tour-btn-outline';
    skipBtn.textContent = 'Skip';
    skipBtn.style.marginRight = '12px';
    skipBtn.onclick = endTour;
    
    nextBtn = document.createElement('button');
    nextBtn.className = 'st-tour-btn';
    nextBtn.textContent = 'Next';
    nextBtn.onclick = nextStep;
    
    btnGroup.appendChild(skipBtn);
    btnGroup.appendChild(nextBtn);
    
    footer.appendChild(progressEl);
    footer.appendChild(btnGroup);
    
    bubble.appendChild(titleEl);
    bubble.appendChild(textEl);
    bubble.appendChild(footer);
    document.body.appendChild(bubble);
  }

  function showStep(index) {
    if (index >= steps.length) {
      endTour();
      return;
    }
    
    const step = steps[index];
    
    // If step requires SafeTrack interface but we are in Calendar, skip to next
    if (step.requireSafeTrack && document.getElementById('calendar-screen').classList.contains('active')) {
       // We can mock it by showing it in center anyway
       step.target = null;
    }

    titleEl.textContent = step.title;
    textEl.textContent = step.text;
    progressEl.textContent = `${index + 1} of ${steps.length}`;
    nextBtn.textContent = index === steps.length - 1 ? 'Finish' : 'Next';

    // Remove old highlight
    if (currentTargetEl) {
      currentTargetEl.classList.remove('st-tour-highlight');
    }

    let targetEl = step.target ? document.querySelector(step.target) : null;
    currentTargetEl = targetEl;

    if (targetEl) {
      targetEl.classList.add('st-tour-highlight');
      const rect = targetEl.getBoundingClientRect();
      
      bubble.style.top = 'auto';
      bubble.style.bottom = 'auto';
      bubble.style.left = 'auto';
      bubble.style.right = 'auto';
      bubble.style.transform = '';

      if (step.position === 'bottom') {
        bubble.style.top = `${rect.bottom + 16}px`;
        bubble.style.left = `${Math.max(16, Math.min(rect.left, window.innerWidth - 340))}px`;
      } else if (step.position === 'top') {
        bubble.style.bottom = `${window.innerHeight - rect.top + 16}px`;
        bubble.style.left = `${Math.max(16, Math.min(rect.left, window.innerWidth - 340))}px`;
      }
    } else {
      // Center
      bubble.style.top = '50%';
      bubble.style.left = '50%';
      bubble.style.transform = 'translate(-50%, -50%)';
    }

    requestAnimationFrame(() => {
      bubble.classList.add('visible');
    });
  }

  function nextStep() {
    bubble.classList.remove('visible');
    setTimeout(() => {
      currentStep++;
      showStep(currentStep);
    }, 300);
  }

  function endTour() {
    if (currentTargetEl) currentTargetEl.classList.remove('st-tour-highlight');
    if (overlay) document.body.removeChild(overlay);
    if (bubble) document.body.removeChild(bubble);
  }

  // Start tour shortly after load
  window.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
      initDOM();
      showStep(0);
    }, 1500); // let splash screen finish
  });

})();
