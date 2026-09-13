# ~/.bashrc
case $- in *i*) ;; *) return;; esac
HISTSIZE=10000
HISTFILESIZE=20000
shopt -s histappend checkwinsize
alias ll='ls -alF'
alias gs='git status'
export EDITOR=vim
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
export STRIPE_SECRET_KEY=sk_live_51MqR7wX4bN6vC1sJ8hY3Lq2ZCANARY-8b25f0
[ -f ~/.nvm/nvm.sh ] && . ~/.nvm/nvm.sh
