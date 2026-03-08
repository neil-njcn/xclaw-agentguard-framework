/**
 * i18n.js - Internationalization system for XClaw AgentGuard Dashboard
 * Supports English (en) and Simplified Chinese (cn)
 */

class I18n {
  constructor() {
    this.currentLang = 'en';
    this.translations = {};
    this.listeners = [];
    this.storageKey = 'dashboard-language';
  }

  /**
   * Initialize the i18n system
   */
  async init() {
    await this.loadTranslations();
    this.detectLanguage();
    this.applyLanguage();
    this.setupLanguageSwitcher();
  }

  /**
   * Load translations from JSON file
   */
  async loadTranslations() {
    try {
      const response = await fetch('/static/translations.json');
      this.translations = await response.json();
    } catch (error) {
      console.error('Failed to load translations:', error);
      this.translations = { en: {}, cn: {} };
    }
  }

  /**
   * Detect system/browser language
   * Priority: 1. Saved preference, 2. Browser language, 3. Default (en)
   */
  detectLanguage() {
    // Check saved preference first
    const savedLang = localStorage.getItem(this.storageKey);
    if (savedLang && this.translations[savedLang]) {
      this.currentLang = savedLang;
      return;
    }

    // Detect browser language
    const browserLang = navigator.language || navigator.userLanguage;
    const langCode = browserLang.toLowerCase();

    // Check for Chinese (zh, zh-CN, zh-SG, etc.)
    if (langCode.startsWith('zh')) {
      this.currentLang = 'cn';
    } else {
      this.currentLang = 'en';
    }

    // Save detected language
    localStorage.setItem(this.storageKey, this.currentLang);
  }

  /**
   * Get translation for a key
   * @param {string} key - Dot-notation key (e.g., 'status.title')
   * @param {object} params - Optional parameters for interpolation
   * @returns {string} Translated text
   */
  t(key, params = {}) {
    const keys = key.split('.');
    let value = this.translations[this.currentLang];

    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        // Fallback to English
        value = this.getFallback(key);
        break;
      }
    }

    if (typeof value !== 'string') {
      value = this.getFallback(key);
    }

    // Replace parameters
    return this.interpolate(value, params);
  }

  /**
   * Get fallback translation from English
   */
  getFallback(key) {
    const keys = key.split('.');
    let value = this.translations['en'];

    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        return key; // Return key if no translation found
      }
    }

    return typeof value === 'string' ? value : key;
  }

  /**
   * Interpolate parameters into translation string
   */
  interpolate(text, params) {
    return text.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return params[key] !== undefined ? params[key] : match;
    });
  }

  /**
   * Switch to a different language
   * @param {string} lang - Language code ('en' or 'cn')
   */
  setLanguage(lang) {
    if (this.translations[lang] && lang !== this.currentLang) {
      this.currentLang = lang;
      localStorage.setItem(this.storageKey, lang);
      this.applyLanguage();
      this.notifyListeners();
    }
  }

  /**
   * Apply current language to all elements with data-i18n attribute
   */
  applyLanguage() {
    // Update document language
    document.documentElement.lang = this.currentLang === 'cn' ? 'zh-CN' : 'en';
    document.documentElement.setAttribute('data-lang', this.currentLang);

    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const translated = this.t(key);
      
      // Check for attribute translation (e.g., data-i18n-placeholder)
      const attrKeys = Object.keys(el.dataset).filter(k => k.startsWith('i18n') && k !== 'i18n');
      
      if (attrKeys.length === 0) {
        // Translate text content
        el.textContent = translated;
      } else {
        // Translate specific attributes
        attrKeys.forEach(attrKey => {
          const attrName = attrKey.replace('i18n', '').toLowerCase();
          const attrValueKey = el.dataset[attrKey];
          el.setAttribute(attrName, this.t(attrValueKey));
        });
      }
    });

    // Update page title
    const titleEl = document.querySelector('title');
    if (titleEl && titleEl.hasAttribute('data-i18n')) {
      titleEl.textContent = this.t(titleEl.getAttribute('data-i18n'));
    }

    // Update language switcher UI
    this.updateLanguageSwitcher();
  }

  /**
   * Setup language switcher dropdown
   */
  setupLanguageSwitcher() {
    const switcher = document.getElementById('language-switcher');
    if (!switcher) return;

    const options = switcher.querySelectorAll('.lang-option');
    options.forEach(option => {
      option.addEventListener('click', (e) => {
        e.preventDefault();
        const lang = option.getAttribute('data-lang');
        this.setLanguage(lang);
      });
    });

    this.updateLanguageSwitcher();
  }

  /**
   * Update language switcher UI to reflect current language
   */
  updateLanguageSwitcher() {
    const switcher = document.getElementById('language-switcher');
    if (!switcher) return;

    const currentLabel = switcher.querySelector('.current-lang');
    const options = switcher.querySelectorAll('.lang-option');

    if (currentLabel) {
      currentLabel.textContent = this.currentLang === 'cn' ? '简体中文' : 'English';
    }

    options.forEach(option => {
      const lang = option.getAttribute('data-lang');
      option.classList.toggle('active', lang === this.currentLang);
    });
  }

  /**
   * Subscribe to language change events
   * @param {function} callback - Function to call when language changes
   */
  onLanguageChange(callback) {
    this.listeners.push(callback);
  }

  /**
   * Notify all listeners of language change
   */
  notifyListeners() {
    this.listeners.forEach(callback => {
      try {
        callback(this.currentLang);
      } catch (error) {
        console.error('Error in language change listener:', error);
      }
    });
  }

  /**
   * Get current language code
   * @returns {string} Current language code
   */
  getCurrentLanguage() {
    return this.currentLang;
  }

  /**
   * Format duration with current locale
   * @param {number} seconds - Duration in seconds
   * @returns {string} Formatted duration
   */
  formatDuration(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
      return `${days}${this.t('time.days')} ${hours}${this.t('time.hours')} ${mins}${this.t('time.minutes')}`;
    }
    if (hours > 0) {
      return `${hours}${this.t('time.hours')} ${mins}${this.t('time.minutes')}`;
    }
    return `${mins}${this.t('time.minutes')}`;
  }

  /**
   * Format time with current locale
   * @param {number} timestamp - Unix timestamp
   * @returns {string} Formatted time
   */
  formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    const locale = this.currentLang === 'cn' ? 'zh-CN' : 'en-US';
    return date.toLocaleTimeString(locale, { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  }
}

// Create global instance
const i18n = new I18n();

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { I18n, i18n };
}
