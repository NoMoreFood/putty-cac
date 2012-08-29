;; -*-emacs-lisp-*-

;; repeat-complex-command is C-x Esc Esc
;; you like this.

(require 'generic-x)
(add-to-list 'generic-extras-enable-list 'javascript-generic-mode)

(fset 'revert-buffer-no-kidding
   [?\M-x ?r ?e ?v ?e ?r ?t ?- ?b ?u tab return ?y ?e ?s return])
(global-set-key (quote [f11]) (quote revert-buffer-no-kidding))

(if (eq window-system 'mac) 
    (progn 
      (set-cursor-color "red")
      (set-foreground-color "khaki")
      (set-background-color "MidnightBlue")))

(setq auto-save-list-file-prefix "~/.saves/")
(global-set-key "" 'backward-delete-char)
(global-set-key '[S-right] 'forward-word)
(global-set-key '[S-left] 'backward-word)
(global-set-key "\C-\\" 'select-from-buffer-list)
(global-set-key "\M-." 'find-tag-other-window)
;(global-set-key "\C-o" 'other-window)
(global-set-key '[select] 'delete-char)

(global-set-key "\C-xc" 'save-buffers-kill-emacs)
(global-set-key "\C-xG" 'goto-line)
(global-set-key "\C-xS" 'save-buffer)
(global-set-key "\M-\C-p" (fset 'slide "1\366"))
(global-set-key "\M-\C-n" (fset 'slide "1"))

(defun up-slightly () (interactive) (scroll-up 5))
(defun down-slightly () (interactive) (scroll-down 5))
(global-set-key [mouse-4] 'down-slightly)
(global-set-key [mouse-5] 'up-slightly)

(defun up-one () (interactive) (scroll-up 1))
(defun down-one () (interactive) (scroll-down 1))
(global-set-key [S-mouse-4] 'down-one)
(global-set-key [S-mouse-5] 'up-one)

(defun up-a-lot () (interactive) (scroll-up))
(defun down-a-lot () (interactive) (scroll-down))
(global-set-key [C-mouse-4] 'down-a-lot)
(global-set-key [C-mouse-5] 'up-a-lot)

(fset 'get-gnus-no-server
   [?\M-x ?g ?n ?u ?s ?- ?n ?o ?- ?s ?e ?r ?v ?e ?r return ?3 ?l ?g home up])
(global-set-key '[f9] 'get-gnus-no-server)
(global-set-key '[f10] 
		(lambda (arg)
		  (interactive "p")
		  (shell-command (expand-file-name "~/bin/get_mail"))
		  (if arg
		      (gnus arg)
		    (gnus-no-server 3))))
(fset 'revert-buffer-no-kidding
   [?\M-x ?r ?e ?v ?e ?r ?t ?- ?b ?u tab return ?y ?e ?s return])
(global-set-key (quote [f11]) (quote revert-buffer-no-kidding))
(global-set-key (quote [f12]) (quote other-window))
(global-set-key (quote [f13]) (quote from))
(global-set-key (quote [f14]) (quote other-window))
(global-set-key '[S-tab]
		(lambda ()
		  (interactive)
		  (insert-tab)))
(if window-system
      (global-set-key "\C-z" 'bury-buffer))
;; ***********************************************************************
;; By an unknown contributor - typing "%" on any paren/bracket takes you to
;; its matched paren/bracket
;; **********************************************************************

(defun match-paren (arg)
"Go to the matching parenthesis if on parenthesis otherwise insert %."
      (interactive "p")
      (cond ((looking-at "\\s\(") (forward-list 1) (backward-char 1))
	    ((looking-at "\\s\)") (forward-char 1) (backward-list 1))
	    (t (self-insert-command (or arg 1)))))
(global-set-key "%" 'match-paren)

(autoload 'term (expand-file-name "~/elisp/eterm/term.el") nil t)
(autoload 'generic-code-mode (expand-file-name "~/elisp/gener-code.el") nil t)

(autoload 'actionscript-mode (expand-file-name "~/elisp/actionscript-mode.el") nil t)
(setq default-major-mode 'fundamental-mode)
(setq text-mode-hook 'turn-on-auto-fill)
(setq tex-mode-hook 'turn-on-auto-fill)
(setq outline-mode-hook 'turn-on-auto-fill)
(setq outline-regexp "\\\\[a-z]*section")
(setq search-slow-window-lines 3)
(setq explicit-shell-file-name nil)
(setq mouse-yank-at-point t)
(setq inhibit-default-init t)
(setq load-path (cons (expand-file-name "/home/magnus/elisp") load-path))
(setq load-path (cons (expand-file-name "~/elisp") load-path))
(setq load-path (cons "/usr/share/emacs/site-lisp" load-path))
(setq load-path (cons "/usr/share/emacs/site-lisp/zenirc" load-path))
(load "dan-mail-hist" t t)
;(load "vc-svn" t t)
(setq dabbrev-case-fold-search nil)
;(setq special-display-buffer-names
;      '("RMAIL" "*Group*" "*compilation*"))
(server-start)

(remove-hook 'kill-buffer-query-functions
 	  'server-kill-buffer-query-function)
(remove-hook 'kill-emacs-query-functions
	  'server-kill-emacs-query-function)   

(defun server-kill-buffer-done-function ()
  (if server-buffer-clients
      (server-buffer-done (current-buffer))))

(add-hook 'kill-buffer-hook
	  'server-kill-buffer-done-function)      

(defun select-from-buffer-list ()
  "Get list of buffers, and put cursor on second item in list."
  (interactive)
  (list-buffers)
  (other-window 1)
  (next-line 3)
  (beginning-of-line))

(load "~/elisp/win-reg" t t)

;;;  Dan's athena .emacs file

;(if (and window-system (x-display-color-p))
;    (progn
;      (set-cursor-color "red")
;      (set-mouse-color "white")
;      (set-foreground-color "Aquamarine")
;      (set-background-color "gray5")
;      (set-face-background 'modeline "antiquewhite")
;      (set-face-foreground 'modeline "black")
;      (set-face-background 'highlight "black")
;      (set-face-background 'region "MidnightBlue")))

;(if (not window-system)
;    (load "~/elisp/macmouse.el" t t))

(setq mail-header-separator "*** PRAISE BE TO EMACS THE ALL POWERFUL ***")
(setq make-backup-files nil)
(setq truncate-partial-width-windows nil)
(setq terminal-fascism nil)
(setq mail-default-reply-to "Daniel Risacher <magnus@alum.mit.edu>")
;(load-library "~/elisp/danterm.elc")
(load "~/elisp/danterm2.el" t t) 
(define-key ctl-x-map "t" 'terminal-emulator)
(load "~/elisp/danwin.el" t t)

;;;;;;;;;;
;; gnus ;;
;;;;;;;;;;
(setq load-path (cons (expand-file-name "~/elisp/gnus-5.10.6/lisp") load-path))
;(setq load-path (cons (expand-file-name "~/elisp/ognus-0.24/lisp") load-path))
;(setq load-path (cons (expand-file-name "~/elisp/gnus-5.8.7/lisp") load-path))
;(setq gnus-nntp-server "netnews.worldnet.att.net")
;(autoload 'gnus "guns" "Read network news." t)
;(autoload 'gnus-post-news "gnuspost" "Post a new news." t)

(defun gnus-browse-imaps-server (server)
        "Browse a mail server in Gnus via IMAP-SSL."
        (interactive "sServer name: ")
        (gnus-group-browse-foreign-server
          (list 'nnimap server
             (list 'nnimap-address server)
             '(nnimap-stream ssl)
             '(nnimap-list-pattern ("INBOX" "mail/*" "Mail/*" "INBOX.*"))
             '(nnimap-expunge-on-close ask))))



(load "~/elisp/x-size" t t)

; #  keep from using down arrow past end of window
(setq next-line-add-newlines nil)

;(setq find-file-hooks (cons 'my-set-title find-file-hooks))

(put 'eval-expression 'disabled nil)
;(put 'suspend-emacs 'disabled nil)
(put 'upcase-region 'disabled nil)
(put 'downcase-region 'disabled nil)
(put 'dired-other-window 'disabled t)
(put 'narrow-to-region 'disabled nil)

(autoload 'maniac-fill-mode "maniac" nil t)
(autoload 'exclude-minor-mode "exclude" nil t)

(setq load-path (cons (expand-file-name "~/elisp/w3") load-path))
(autoload 'w3-preview-this-buffer "w3" "WWW Previewer" t)
(autoload 'w3-follow-url-at-point "w3" "Find document at pt" t)
(autoload 'w3 "w3" "WWW Browser" t)
(autoload 'w3-open-local "w3" "Open local file for WWW browsing" t)
(autoload 'w3-fetch "w3" "Open remote file for WWW browsing" t)
(autoload 'w3-use-hotlist "w3" "Use shortcuts to view WWW docs" t)
(autoload 'w3-show-hotlist "w3" "Use shortcuts to view WWW docs" t)
(autoload 'w3-follow-link "w3" "Follow a hypertext link." t)
(autoload 'w3-batch-fetch "w3" "Batch retrieval of URLs" t)
(autoload 'url-get-url-at-point "url" "Find the url under the cursor" nil)
(autoload 'url-file-attributes  "url" "File attributes of a URL" nil)
(autoload 'url-popup-info "url" "Get info on a URL" t)
(autoload 'url-retrieve   "url" "Retrieve a URL" nil)
(autoload 'url-buffer-visiting "url" "Find buffer visiting a URL." nil)

(autoload 'gopher-dispatch-object "gopher" "Fetch gopher dir" t)


(setq auto-mode-alist (cons (cons "\\.stk\\'" 'scheme-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.html\\'" 'html-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.txt\\'" 'text-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.xc\\'" 'c-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.xh\\'" 'c-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.t\\'" 'c-mode) auto-mode-alist))
(setq auto-mode-alist (cons (cons "\\.as\\'" 'actionscript-mode) auto-mode-alist))


;(autoload 'html-mode "html-mode" "HTML major mode." t)
(or (assoc "\\.html$" auto-mode-alist)
    (setq auto-mode-alist (cons '("\\.html$" . html-mode) 
				auto-mode-alist)))
(autoload 'sc-cite-original     "supercite" "Supercite 3.1" t)
(autoload 'sc-submit-bug-report "supercite" "Supercite 3.1" t)
(add-hook 'mail-citation-hook 'sc-cite-original)
(setq message-cite-function 'sc-cite-original)
(setq news-reply-header-hook nil)

(autoload 'zenirc "zenirc" "zenirc - IRC client" t)
(setq zenirc-server-default "irc2.posixnap.net")
;(modify-syntax-entry ?\- "w" scheme-mode-syntax-table)
(setq inhibit-startup-message 't)
(setq inhibit-startup-echo-area-message "magnus")
;(setq rmail-file-name "~/Mail/RMAIL")

(defun yak ()
  (interactive)
  (local-set-key "{" 'self-insert-command)
  (local-set-key "}" 'self-insert-command))

(defun small-tabs ()
  (interactive)
  (setq tab-width 4)
  (local-set-key '[tab] 		
		 (lambda ()
		   (interactive)
		   (insert-tab))))

;(autoload 'format-lisp-code-directory "lispdir" nil t)
;(autoload 'lisp-dir-apropos "lispdir" nil t)
;(autoload 'lisp-dir-retrieve "lispdir" nil t)
;(autoload 'lisp-dir-verify "lispdir" nil t)
(autoload 'praise-emacs "praise" nil t)
(autoload 'inquir "inquir" "The inquir front-end" t)

;(if (eq window-system 'x)
;    (x-full-screen))

;(load (expand-file-name "~/elisp/time.el") t t)

(setq frame-title-format '(multiple-frames "Dan - %b" ("" "Dan's emacs @ " system-name)))    
(auto-compression-mode 1)

(defun linux-c-mode ()
  "C mode with adjusted defaults for use with the Linux kernel."
  (interactive)
  (c-mode)
  (setq c-indent-level 8)
  (setq c-brace-imaginary-offset 0)
  (setq c-brace-offset -8)
  (setq c-argdecl-indent 8)
  (setq c-label-offset -8)
  (setq c-continued-statement-offset 8)
  (setq indent-tabs-mode nil)
  (setq tab-width 8))

;(normal-top-level-add-to-load-path '("apel" "bitmap" "mu" "mel" "semi"))

;(setq top-level-site-lisp-dir "/usr/local/emacs-20.2/share/emacs/site-lisp/")
;(setq load-path (cons (concat top-level-site-lisp-dir "apel") load-path))
;(setq load-path (cons (concat top-level-site-lisp-dir "bitmap") load-path))
;(setq load-path (cons (concat top-level-site-lisp-dir "mu") load-path))
;(setq load-path (cons (concat top-level-site-lisp-dir "mel") load-path))
;(setq load-path (cons (concat top-level-site-lisp-dir "semi") load-path))

;(load "gnus-mime-setup")

(setq user-mail-address "magnus@alum.mit.edu")
(setq query-replace-highlight t)

(global-set-key (quote [home]) (quote beginning-of-buffer))
(global-set-key (quote [end]) (quote end-of-buffer))

;(add-hook 'c-mode-hook 'font-lock-mode)
(global-font-lock-mode 1)

;(load-library "mailcrypt") ; provides "mc-setversion"
;(mc-setversion "gpg")    ; for PGP 2.6 (default); also "5.0" and "gpg"
;(autoload 'mc-install-write-mode "mailcrypt" nil t)
;(autoload 'mc-install-read-mode "mailcrypt" nil t)
;(add-hook 'mail-mode-hook 'mc-install-write-mode)
;(add-hook 'gnus-summary-mode-hook 'mc-install-read-mode)
;(add-hook 'gnus-article-mode-hook 'mc-install-read-mode)
;(add-hook 'message-mode-hook 'mc-install-write-mode)
;(add-hook 'rmail-show-message-hook 'mc-install-read-mode)
;(add-hook 'rmail-summary-mode-hook 'mc-install-read-mode)
;(add-hook 'news-reply-mode-hook 'mc-install-write-mode)

;(tool-bar-mode 0)

(autoload 'gpg-after-find-file "gpg" nil t)
(add-hook 'find-file-hooks 'gpg-after-find-file)


(message "Wuggity, wuggity, wuggity.")
(custom-set-variables
  ;; custom-set-variables was added by Custom.
  ;; If you edit it by hand, you could mess it up, so be careful.
  ;; Your init file should contain only one such instance.
  ;; If there is more than one, they won't work right.
 '(browse-url-browser-function (quote browse-url-gnome-moz))
 '(lpr-page-header-switches (quote ("-f" "-l" "60")))
 '(mail-envelope-from nil)
 '(mail-from-style (quote angles))
 '(mail-specify-envelope-from t)
 '(nnimap-split-crosspost nil)
 '(printer-name "allinone")
 '(safe-local-variable-values (quote ((c-basic-indent . 4)))))
(custom-set-faces
  ;; custom-set-faces was added by Custom.
  ;; If you edit it by hand, you could mess it up, so be careful.
  ;; Your init file should contain only one such instance.
  ;; If there is more than one, they won't work right.
 )
