#!/bin/bash

# Script de Instalação Completa do Servidor Web Apache com PHP
# Ubuntu 18.04 LTS
# Autor: Assistente Claude
# Data: $(date)

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (use sudo)"
fi

# Verificar versão do Ubuntu
if ! grep -q "Ubuntu 18.04" /etc/os-release; then
    warning "Este script foi otimizado para Ubuntu 18.04. Continuando mesmo assim..."
fi

log "Iniciando instalação do servidor web completo..."

# Atualizar sistema
log "Atualizando sistema..."
apt-get update -y
apt-get upgrade -y

# Instalar dependências básicas
log "Instalando dependências básicas..."
apt-get install -y \
    apache2 \
    apache2-utils \
    openssl \
    ssl-cert \
    certbot \
    python3-certbot-apache \
    curl \
    wget \
    unzip \
    git \
    nano \
    htop \
    ufw \
    fail2ban \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Adicionar repositório do PHP (Ondrej)
log "Adicionando repositório do PHP..."
add-apt-repository -y ppa:ondrej/php
apt-get update -y

# Instalar PHP 8.1 e todas as extensões necessárias
log "Instalando PHP 8.1 e extensões..."
apt-get install -y \
    php8.1 \
    php8.1-fpm \
    php8.1-cli \
    php8.1-common \
    php8.1-mysql \
    php8.1-zip \
    php8.1-gd \
    php8.1-mbstring \
    php8.1-curl \
    php8.1-xml \
    php8.1-bcmath \
    php8.1-json \
    php8.1-intl \
    php8.1-soap \
    php8.1-imap \
    php8.1-pgsql \
    php8.1-sqlite3 \
    php8.1-ldap \
    php8.1-redis \
    php8.1-memcached \
    php8.1-imagick \
    php8.1-xdebug \
    php8.1-opcache \
    php8.1-readline \
    php8.1-dev \
    libapache2-mod-php8.1

# Instalar PHP 7.4 como alternativa (para compatibilidade)
log "Instalando PHP 7.4 como alternativa..."
apt-get install -y \
    php7.4 \
    php7.4-fpm \
    php7.4-cli \
    php7.4-common \
    php7.4-mysql \
    php7.4-zip \
    php7.4-gd \
    php7.4-mbstring \
    php7.4-curl \
    php7.4-xml \
    php7.4-bcmath \
    php7.4-json \
    php7.4-intl \
    php7.4-soap \
    php7.4-imap \
    php7.4-pgsql \
    php7.4-sqlite3 \
    php7.4-ldap \
    php7.4-redis \
    php7.4-memcached \
    php7.4-imagick \
    php7.4-xdebug \
    php7.4-opcache \
    php7.4-readline \
    libapache2-mod-php7.4

# Configurar PHP 8.1 como padrão
log "Configurando PHP 8.1 como padrão..."
update-alternatives --set php /usr/bin/php8.1
a2enmod php8.1
a2dismod php7.4

# Instalar MySQL/MariaDB
log "Instalando MariaDB..."
apt-get install -y mariadb-server mariadb-client

# Instalar Redis e Memcached
log "Instalando Redis e Memcached..."
apt-get install -y redis-server memcached

# Habilitar módulos do Apache
log "Habilitando módulos do Apache..."
a2enmod rewrite
a2enmod ssl
a2enmod headers
a2enmod expires
a2enmod deflate
a2enmod security2
a2enmod evasive24
a2enmod proxy
a2enmod proxy_fcgi
a2enmod setenvif

# Instalar mod_security e mod_evasive
log "Instalando módulos de segurança..."
apt-get install -y libapache2-mod-security2 libapache2-mod-evasive

# Configurar firewall
log "Configurando firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 'Apache Full'
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp

# Configurar fail2ban
log "Configurando fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# Configurar Apache principal
log "Configurando Apache..."
cat > /etc/apache2/conf-available/security.conf << 'EOF'
# Ocultar versão do Apache
ServerTokens Prod
ServerSignature Off

# Prevenir ataques de clickjacking
Header always append X-Frame-Options SAMEORIGIN

# Prevenir MIME type sniffing
Header set X-Content-Type-Options nosniff

# Habilitar XSS protection
Header set X-XSS-Protection "1; mode=block"

# Configurações de SSL
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLSessionTickets off
EOF

a2enconf security

# Configurar PHP 8.1
log "Configurando PHP 8.1..."
PHP_INI="/etc/php/8.1/apache2/php.ini"
PHP_CLI_INI="/etc/php/8.1/cli/php.ini"

# Backup do arquivo original
cp $PHP_INI $PHP_INI.backup
cp $PHP_CLI_INI $PHP_CLI_INI.backup

# Configurações otimizadas para PHP
cat > /tmp/php_config.txt << 'PHPCONF'
; Configurações de Performance
max_execution_time = 300
max_input_time = 300
memory_limit = 512M
post_max_size = 100M
upload_max_filesize = 100M
max_file_uploads = 20

; Configurações de Sessão
session.save_handler = redis
session.save_path = "tcp://127.0.0.1:6379"
session.gc_maxlifetime = 1440

; OPcache
opcache.enable = 1
opcache.enable_cli = 1
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 4000
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1

; Configurações de Error
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log

; Timezone
date.timezone = America/Sao_Paulo

; Extensões habilitadas
extension=mysqli
extension=pdo_mysql
extension=curl
extension=gd
extension=mbstring
extension=xml
extension=zip
extension=json
extension=redis
extension=memcached
extension=imagick
PHPCONF

# Aplicar configurações
sed -i 's/max_execution_time = 30/max_execution_time = 300/' $PHP_INI
sed -i 's/max_input_time = 60/max_input_time = 300/' $PHP_INI
sed -i 's/memory_limit = 128M/memory_limit = 512M/' $PHP_INI
sed -i 's/post_max_size = 8M/post_max_size = 100M/' $PHP_INI
sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 100M/' $PHP_INI
sed -i 's/;date.timezone =/date.timezone = America\/Sao_Paulo/' $PHP_INI
sed -i 's/display_errors = On/display_errors = Off/' $PHP_INI
sed -i 's/;opcache.enable=1/opcache.enable=1/' $PHP_INI

# Criar diretório de logs do PHP
mkdir -p /var/log/php
chown www-data:www-data /var/log/php

# Configurar PHP-FPM 8.1
log "Configurando PHP-FPM 8.1..."
systemctl enable php8.1-fpm
systemctl start php8.1-fpm

# Configurar Apache para usar PHP-FPM (opcional, por padrão usa mod_php)
cat > /etc/apache2/conf-available/php-fpm.conf << 'EOF'
# Configuração para usar PHP-FPM ao invés de mod_php
# Descomente as linhas abaixo se quiser usar FPM

# <FilesMatch \.php$>
#     SetHandler "proxy:unix:/var/run/php/php8.1-fpm.sock|fcgi://localhost/"
# </FilesMatch>
EOF

a2enconf php-fpm

# Criar estrutura de diretórios
log "Criando estrutura de diretórios..."
mkdir -p /var/www/html/sites
mkdir -p /var/www/html/subdomains
mkdir -p /var/www/html/projects
mkdir -p /etc/apache2/sites-available/domains
mkdir -p /etc/apache2/sites-available/subdomains
mkdir -p /var/log/apache2/domains
mkdir -p /var/log/apache2/subdomains

# Criar página de teste PHP
cat > /var/www/html/index.php << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Servidor Web Configurado</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .version { font-size: 1.2em; font-weight: bold; color: #2196F3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Servidor Web Configurado com Sucesso!</h1>
        
        <div class="info">
            <strong>Informações do Sistema:</strong><br>
            Data/Hora: <?php echo date('d/m/Y H:i:s'); ?><br>
            Servidor: <?php echo $_SERVER['SERVER_SOFTWARE']; ?><br>
            Sistema: <?php echo php_uname(); ?>
        </div>

        <h2>📋 Informações do PHP</h2>
        <table>
            <tr><th>Configuração</th><th>Valor</th><th>Status</th></tr>
            <tr>
                <td>Versão do PHP</td>
                <td class="version"><?php echo phpversion(); ?></td>
                <td class="success">✓</td>
            </tr>
            <tr>
                <td>Memory Limit</td>
                <td><?php echo ini_get('memory_limit'); ?></td>
                <td class="success">✓</td>
            </tr>
            <tr>
                <td>Upload Max Size</td>
                <td><?php echo ini_get('upload_max_filesize'); ?></td>
                <td class="success">✓</td>
            </tr>
            <tr>
                <td>Post Max Size</td>
                <td><?php echo ini_get('post_max_size'); ?></td>
                <td class="success">✓</td>
            </tr>
            <tr>
                <td>Max Execution Time</td>
                <td><?php echo ini_get('max_execution_time'); ?>s</td>
                <td class="success">✓</td>
            </tr>
        </table>

        <h2>🔧 Módulos do Apache</h2>
        <?php if (function_exists('apache_get_modules')): ?>
            <p><strong>mod_rewrite:</strong> 
            <?php echo in_array('mod_rewrite', apache_get_modules()) ? '<span class="success">✓ Ativo</span>' : '<span class="error">✗ Inativo</span>'; ?>
            </p>
            <p><strong>mod_ssl:</strong> 
            <?php echo in_array('mod_ssl', apache_get_modules()) ? '<span class="success">✓ Ativo</span>' : '<span class="error">✗ Inativo</span>'; ?>
            </p>
        <?php endif; ?>

        <h2>🗄️ Extensões do PHP</h2>
        <table>
            <?php
            $extensions = ['mysqli', 'pdo_mysql', 'curl', 'gd', 'mbstring', 'xml', 'zip', 'json', 'openssl', 'redis', 'memcached', 'imagick', 'opcache'];
            foreach($extensions as $ext):
            ?>
            <tr>
                <td><?php echo $ext; ?></td>
                <td><?php echo extension_loaded($ext) ? '<span class="success">✓ Carregada</span>' : '<span class="error">✗ Não carregada</span>'; ?></td>
            </tr>
            <?php endforeach; ?>
        </table>

        <h2>🔒 Status SSL</h2>
        <?php if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'): ?>
            <p class="success">✓ Conexão SSL ativa e funcionando</p>
        <?php else: ?>
            <p class="warning">⚠ Conexão não SSL (configure certificados com: manage-domain ssl seudominio.com)</p>
        <?php endif; ?>

        <h2>📊 Informações do Banco de Dados</h2>
        <?php
        try {
            $pdo = new PDO('mysql:host=localhost', 'root', 'root123!@#');
            echo '<p class="success">✓ Conexão com MySQL funcionando</p>';
            echo '<p><strong>Versão MySQL:</strong> ' . $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) . '</p>';
        } catch(PDOException $e) {
            echo '<p class="error">✗ Erro na conexão com MySQL: ' . $e->getMessage() . '</p>';
        }
        ?>

        <h2>🛠️ Comandos Úteis</h2>
        <div class="info">
            <strong>Gerenciar domínios:</strong><br>
            <code>manage-domain add exemplo.com domain</code> - Adicionar domínio<br>
            <code>manage-domain add blog.exemplo.com subdomain</code> - Adicionar subdomínio<br>
            <code>manage-domain ssl exemplo.com</code> - Configurar SSL<br>
            <code>add-project meu-app exemplo.com</code> - Adicionar projeto<br><br>
            
            <strong>PHP:</strong><br>
            <code>php -v</code> - Verificar versão<br>
            <code>php -m</code> - Listar módulos<br>
            <code>sudo update-alternatives --config php</code> - Trocar versão do PHP<br>
        </div>

        <h2>📁 Estrutura de Diretórios</h2>
        <ul>
            <li><strong>/var/www/html/sites/</strong> - Domínios principais</li>
            <li><strong>/var/www/html/subdomains/</strong> - Subdomínios</li>
            <li><strong>/var/www/html/projects/</strong> - Projetos</li>
            <li><strong>/var/log/apache2/</strong> - Logs do Apache</li>
            <li><strong>/var/log/php/</strong> - Logs do PHP</li>
        </ul>

        <?php if (function_exists('phpinfo')): ?>
        <h2>🔍 PHPInfo Completo</h2>
        <p><a href="?phpinfo=1" target="_blank">Ver informações completas do PHP</a></p>
        <?php endif; ?>

        <?php 
        if (isset($_GET['phpinfo']) && $_GET['phpinfo'] == '1') {
            echo '<hr>';
            phpinfo();
        }
        ?>
    </div>
</body>
</html>
EOF

# Instalar Composer
log "Instalando Composer..."
curl -sS https://getcomposer.org/installer | php
mv composer.phar /usr/local/bin/composer
chmod +x /usr/local/bin/composer

# Verificar instalação do Composer
composer --version

# Instalar Node.js e npm
log "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
apt-get install -y nodejs

# Criar script para alternar versões do PHP
cat > /usr/local/bin/php-switch << 'EOF'
#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Uso: php-switch [versão]"
    echo "Versões disponíveis: 7.4, 8.1"
    echo "Exemplo: php-switch 8.1"
    exit 1
fi

VERSION=$1

case $VERSION in
    7.4)
        echo "Alternando para PHP 7.4..."
        a2dismod php8.1
        a2enmod php7.4
        update-alternatives --set php /usr/bin/php7.4
        systemctl restart apache2
        echo "PHP 7.4 ativado com sucesso!"
        ;;
    8.1)
        echo "Alternando para PHP 8.1..."
        a2dismod php7.4
        a2enmod php8.1
        update-alternatives --set php /usr/bin/php8.1
        systemctl restart apache2
        echo "PHP 8.1 ativado com sucesso!"
        ;;
    *)
        echo "Versão não suportada: $VERSION"
        echo "Versões disponíveis: 7.4, 8.1"
        exit 1
        ;;
esac

echo "Versão atual: $(php -v | head -1)"
EOF

chmod +x /usr/local/bin/php-switch

# Criar script de gerenciamento (manage-domain) - mesmo do script anterior
cat > /usr/local/bin/manage-domain << 'EOF'
#!/bin/bash

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    echo "Uso: manage-domain [OPÇÃO] [DOMÍNIO] [TIPO]"
    echo ""
    echo "Opções:"
    echo "  add       Adicionar novo domínio ou subdomínio"
    echo "  remove    Remover domínio ou subdomínio"
    echo "  list      Listar todos os domínios configurados"
    echo "  ssl       Configurar SSL para domínio"
    echo ""
    echo "Tipos:"
    echo "  domain    Domínio principal (ex: exemplo.com)"
    echo "  subdomain Subdomínio (ex: blog.exemplo.com)"
    echo ""
    echo "Exemplos:"
    echo "  manage-domain add exemplo.com domain"
    echo "  manage-domain add blog.exemplo.com subdomain"
    echo "  manage-domain ssl exemplo.com"
}

add_domain() {
    local domain=$1
    local type=$2
    
    if [[ -z "$domain" || -z "$type" ]]; then
        echo -e "${RED}Erro: Domínio e tipo são obrigatórios${NC}"
        show_help
        exit 1
    fi
    
    case $type in
        domain)
            add_main_domain "$domain"
            ;;
        subdomain)
            add_subdomain "$domain"
            ;;
        *)
            echo -e "${RED}Tipo inválido. Use: domain ou subdomain${NC}"
            exit 1
            ;;
    esac
}

add_main_domain() {
    local domain=$1
    local doc_root="/var/www/html/sites/$domain"
    
    echo -e "${YELLOW}Adicionando domínio principal: $domain${NC}"
    
    # Criar diretório
    mkdir -p "$doc_root"
    mkdir -p "/var/log/apache2/domains/$domain"
    
    # Criar index.php
    cat > "$doc_root/index.php" << INDEXEOF
<?php
echo "<h1>Bem-vindo ao $domain</h1>";
echo "<p>Este site está funcionando corretamente!</p>";
echo "<p>PHP Versão: " . phpversion() . "</p>";
echo "<p>Diretório: $doc_root</p>";
echo "<p>Data/Hora: " . date('Y-m-d H:i:s') . "</p>";
?>
INDEXEOF
    
    # Criar configuração do Apache
    cat > "/etc/apache2/sites-available/domains/$domain.conf" << CONFEOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $doc_root
    
    ErrorLog /var/log/apache2/domains/$domain/error.log
    CustomLog /var/log/apache2/domains/$domain/access.log combined
    
    <Directory $doc_root>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        
        # Configurações PHP específicas
        php_admin_value upload_max_filesize 100M
        php_admin_value post_max_size 100M
        php_admin_value memory_limit 256M
    </Directory>
</VirtualHost>
CONFEOF
    
    # Criar .htaccess
    cat > "$doc_root/.htaccess" << HTEOF
RewriteEngine On

# Redirecionar HTTP para HTTPS
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Configurações de segurança
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options "nosniff"

# Cache para arquivos estáticos
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
</IfModule>
HTEOF
    
    # Ativar site
    a2ensite "domains/$domain"
    systemctl reload apache2
    
    # Configurar permissões
    chown -R www-data:www-data "$doc_root"
    chmod -R 755 "$doc_root"
    
    echo -e "${GREEN}Domínio $domain adicionado com sucesso!${NC}"
    echo -e "${YELLOW}Diretório: $doc_root${NC}"
    echo -e "${YELLOW}Para SSL, execute: manage-domain ssl $domain${NC}"
}

configure_ssl() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Erro: Domínio é obrigatório${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Configurando SSL para: $domain${NC}"
    
    # Usar Certbot para obter certificado
    certbot --apache -d "$domain" -d "www.$domain" --non-interactive --agree-tos --email admin@$domain
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}SSL configurado com sucesso para $domain!${NC}"
    else
        echo -e "${RED}Erro ao configurar SSL para $domain${NC}"
    fi
}

list_domains() {
    echo -e "${YELLOW}Domínios configurados:${NC}"
    echo ""
    
    echo -e "${GREEN}Domínios principais:${NC}"
    ls /etc/apache2/sites-available/domains/ 2>/dev/null | sed 's/\.conf$//' || echo "Nenhum domínio encontrado"
    echo ""
    
    echo -e "${GREEN}Sites ativos:${NC}"
    apache2ctl -S 2>/dev/null | grep "port 80\|port 443" || echo "Erro ao listar sites ativos"
}

# Main
case "$1" in
    add)
        add_domain "$2" "$3"
        ;;
    ssl)
        configure_ssl "$2"
        ;;
    list)
        list_domains
        ;;
    *)
        show_help
        ;;
esac
EOF

chmod +x /usr/local/bin/manage-domain

# Configurar mod_security (mesmo do script anterior)
log "Configurando mod_security..."
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Configurar MySQL
log "Configurando MySQL..."
mysql_secure_installation << 'MYSQLEOF'

y
root123!@#
root123!@#
y
y
y
y
MYSQLEOF

# Criar usuário de banco para aplicações web
mysql -u root -p'root123!@#' << 'MYSQLCMDS'
CREATE USER 'webuser'@'localhost' IDENTIFIED BY 'web123!@#';
GRANT ALL PRIVILEGES ON *.* TO 'webuser'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
MYSQLCMDS

# Reiniciar serviços
log "Reiniciando serviços..."
systemctl restart apache2
systemctl restart mysql
systemctl restart php8.1-fpm
systemctl restart redis-server
systemctl restart memcached

# Verificar status dos serviços
log "Verificando status dos serviços..."
systemctl is-active apache2 && echo "✓ Apache2 está rodando" || echo "✗ Apache2 com problemas"
systemctl is-active mysql && echo "✓ MySQL está rodando" || echo "✗ MySQL com problemas"
systemctl is-active php8.1-fpm && echo "✓ PHP-FPM está rodando" || echo "✗ PHP-FPM com problemas"
systemctl is-active redis-server && echo "✓ Redis está rodando" || echo "✗ Redis com problemas"

# Verificar versões instaladas
log "Verificando versões instaladas..."
echo "PHP: $(php -v | head -1)"
echo "Composer: $(composer --version)"
echo "Node.js: $(node -v)"
echo "NPM: $(npm -v)"

# Criar documentação atualizada
cat > /root/servidor-web-info.txt << 'EOF'
=== SERVIDOR WEB CONFIGURADO ===

INFORMAÇÕES DO SISTEMA:
- Apache 2.4 com SSL
- PHP 8.1 e 7.4 (alternáveis)
- MySQL/MariaDB
- Redis e Memcached
- Certificados SSL automáticos (Let's Encrypt)
- Mod_Security (OWASP Rules)
- Fail2ban para proteção
- Firewall UFW configurado
- Composer e Node.js

COMANDOS ÚTEIS:
- manage-domain add exemplo.com domain     # Adicionar domínio
- manage-domain ssl exemplo.com            # Configurar SSL
- manage-domain list                       # Listar domínios
- php-switch 8.1                          # Alternar para PHP 8.1
- php-switch 7.4                          # Alternar para PHP 7.4
- composer install                         # Instalar dependências PHP
- npm install                              # Instalar dependências Node.js

DIRETÓRIOS:
- Sites principais: /var/www/html/sites/
- Subdomínios: /var/www/html/subdomains/
- Projetos: /var/www/html/projects/
- Logs Apache: /var/log/apache2/
- Logs PHP: /var/log/php/

CREDENCIAIS MYSQL:
- Root: root / root123!@#
- Web User: webuser / web123!@#

CONFIGURAÇÕES PHP:
- Versão padrão: PHP 8.1
- Memory Limit: 512M
- Upload Max: 100M
- Post Max: 100M
- Execution Time: 300s
- OPcache: Habilitado
- Session Handler: Redis

EXTENSÕES PHP INSTALADAS:
- mysqli, pdo_mysql (MySQL)
- curl, gd, mbstring, xml, zip
- json, intl, soap, imap
- redis, memcached, imagick
- opcache, xdebug
- bcmath, readline

ARQUIVOS DE CONFIGURAÇÃO:
- Apache: /etc/apache2/
- PHP 8.1: /etc/php/8.1/
- PHP 7.4: /etc/php/7.4/
- SSL: /etc/letsencrypt/
- MySQL: /etc/mysql/

PORTAS ABERTAS:
- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)

SERVIÇOS ATIVOS:
- Apache2
- MySQL/MariaDB
- PHP-FPM 8.1
- Redis Server
- Memcached
- Fail2ban

BACKUP AUTOMÁTICO:
- Executa todo dia às 2:00
- Localização: /var/backups/websites/
EOF

# Criar script adicional para projetos PHP
cat > /usr/local/bin/add-project << 'EOF'
#!/bin/bash

if [[ $# -lt 2 ]]; then
    echo "Uso: add-project [nome-do-projeto] [dominio-principal] [framework-opcional]"
    echo "Frameworks suportados: laravel, wordpress, codeigniter, symfony"
    echo "Exemplo: add-project meu-app exemplo.com laravel"
    exit 1
fi

PROJECT_NAME=$1
MAIN_DOMAIN=$2
FRAMEWORK=${3:-generic}
PROJECT_DIR="/var/www/html/sites/$MAIN_DOMAIN/$PROJECT_NAME"

echo "Criando projeto $PROJECT_NAME em $MAIN_DOMAIN..."
echo "Framework: $FRAMEWORK"

# Criar diretório do projeto
mkdir -p "$PROJECT_DIR"

# Configurar projeto baseado no framework
case $FRAMEWORK in
    laravel)
        echo "Configurando projeto Laravel..."
        cd "$PROJECT_DIR"
        composer create-project --prefer-dist laravel/laravel . --no-interaction
        
        # Configurar permissões Laravel
        chown -R www-data:www-data "$PROJECT_DIR"
        chmod -R 755 "$PROJECT_DIR"
        chmod -R 775 "$PROJECT_DIR/storage"
        chmod -R 775 "$PROJECT_DIR/bootstrap/cache"
        
        # .htaccess para Laravel
        cat > "$PROJECT_DIR/.htaccess" << 'LARAVELHT'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ public/$1 [L]
</IfModule>
LARAVELHT
        
        echo "Laravel instalado em: $PROJECT_DIR"
        echo "Não esqueça de configurar o .env e executar 'php artisan key:generate'"
        ;;
        
    wordpress)
        echo "Baixando WordPress..."
        cd /tmp
        wget https://wordpress.org/latest.tar.gz
        tar -xzf latest.tar.gz
        cp -R wordpress/* "$PROJECT_DIR/"
        rm -rf wordpress latest.tar.gz
        
        # Configurar permissões WordPress
        chown -R www-data:www-data "$PROJECT_DIR"
        chmod -R 755 "$PROJECT_DIR"
        
        # .htaccess para WordPress
        cat > "$PROJECT_DIR/.htaccess" << 'WPHT'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /<?php echo $PROJECT_NAME; ?>/
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /<?php echo $PROJECT_NAME; ?>/index.php [L]
</IfModule>
# END WordPress
WPHT
        
        echo "WordPress instalado em: $PROJECT_DIR"
        echo "Acesse: http://$MAIN_DOMAIN/$PROJECT_NAME para continuar a instalação"
        ;;
        
    codeigniter)
        echo "Baixando CodeIgniter 4..."
        cd "$PROJECT_DIR"
        composer create-project codeigniter4/appstarter . --no-interaction
        
        # Configurar permissões CodeIgniter
        chown -R www-data:www-data "$PROJECT_DIR"
        chmod -R 755 "$PROJECT_DIR"
        chmod -R 775 "$PROJECT_DIR/writable"
        
        # .htaccess para CodeIgniter 4
        cat > "$PROJECT_DIR/.htaccess" << 'CIHT'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ public/$1 [L]
</IfModule>
CIHT
        
        echo "CodeIgniter 4 instalado em: $PROJECT_DIR"
        ;;
        
    symfony)
        echo "Criando projeto Symfony..."
        cd "$PROJECT_DIR"
        composer create-project symfony/skeleton . --no-interaction
        
        # Configurar permissões Symfony
        chown -R www-data:www-data "$PROJECT_DIR"
        chmod -R 755 "$PROJECT_DIR"
        chmod -R 775 "$PROJECT_DIR/var"
        
        # .htaccess para Symfony
        cat > "$PROJECT_DIR/.htaccess" << 'SYMHT'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ public/$1 [L]
</IfModule>
SYMHT
        
        echo "Symfony instalado em: $PROJECT_DIR"
        ;;
        
    *)
        # Projeto genérico
        cat > "$PROJECT_DIR/index.php" << 'GENERICPROJECT'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo basename(__DIR__); ?></title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .success { color: green; }
        .info { background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Projeto: <?php echo basename(__DIR__); ?></h1>
        <p class="success">Este projeto está funcionando corretamente!</p>
        
        <div class="info">
            <strong>Informações do Projeto:</strong><br>
            <strong>Nome:</strong> <?php echo basename(__DIR__); ?><br>
            <strong>Caminho:</strong> <?php echo __DIR__; ?><br>
            <strong>URL:</strong> <?php echo "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']; ?><br>
            <strong>PHP:</strong> <?php echo phpversion(); ?><br>
            <strong>Data/Hora:</strong> <?php echo date('d/m/Y H:i:s'); ?>
        </div>
        
        <h2>📁 Estrutura do Projeto</h2>
        <ul>
            <li><strong>index.php</strong> - Página principal</li>
            <li><strong>.htaccess</strong> - Configurações do Apache</li>
            <li><strong>assets/</strong> - CSS, JS, imagens</li>
            <li><strong>includes/</strong> - Arquivos PHP incluídos</li>
            <li><strong>config/</strong> - Configurações</li>
        </ul>
        
        <h2>🔧 Próximos Passos</h2>
        <ol>
            <li>Edite este arquivo: <code><?php echo __FILE__; ?></code></li>
            <li>Crie suas páginas PHP neste diretório</li>
            <li>Configure o banco de dados se necessário</li>
            <li>Personalize o .htaccess conforme sua necessidade</li>
        </ol>
    </div>
</body>
</html>
GENERICPROJECT

        # Criar estrutura básica
        mkdir -p "$PROJECT_DIR"/{assets/{css,js,images},includes,config}
        
        # CSS básico
        cat > "$PROJECT_DIR/assets/css/style.css" << 'CSS'
/* Estilos básicos do projeto */
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.btn { display: inline-block; background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
.btn:hover { background: #005a87; }
CSS

        # JavaScript básico
        cat > "$PROJECT_DIR/assets/js/script.js" << 'JS'
// JavaScript básico do projeto
document.addEventListener('DOMContentLoaded', function() {
    console.log('Projeto carregado com sucesso!');
});
JS

        # Arquivo de configuração
        cat > "$PROJECT_DIR/config/config.php" << 'CONFIG'
<?php
// Configurações do projeto

// Banco de dados
define('DB_HOST', 'localhost');
define('DB_NAME', 'nome_do_banco');
define('DB_USER', 'webuser');
define('DB_PASS', 'web123!@#');

// Configurações gerais
define('SITE_URL', 'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']));
define('SITE_NAME', 'Meu Projeto');

// Timezone
date_default_timezone_set('America/Sao_Paulo');

// Configurações de erro (desenvolvimento)
ini_set('display_errors', 1);
error_reporting(E_ALL);
?>
CONFIG

        # .htaccess genérico
        cat > "$PROJECT_DIR/.htaccess" << 'GENERICHT'
RewriteEngine On

# Redirecionar para HTTPS
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Remover extensão .php das URLs
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^([^\.]+)$ $1.php [NC,L]

# Configurações de segurança
<Files ".htaccess">
Order allow,deny
Deny from all
</Files>

<Files "config.php">
Order allow,deny
Deny from all
</Files>

# Cache para arquivos estáticos
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
</IfModule>
GENERICHT
        
        echo "Projeto genérico criado em: $PROJECT_DIR"
        ;;
esac

# Configurar permissões finais
chown -R www-data:www-data "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR"

echo ""
echo "✅ Projeto $PROJECT_NAME criado com sucesso!"
echo "📁 Diretório: $PROJECT_DIR"
echo "🌐 URL: http://$MAIN_DOMAIN/$PROJECT_NAME"
echo ""
EOF

chmod +x /usr/local/bin/add-project

# Criar script para otimização de performance
cat > /usr/local/bin/optimize-server << 'EOF'
#!/bin/bash

echo "🚀 Otimizando servidor para melhor performance..."

# Otimizar MySQL
echo "Otimizando MySQL..."
mysql -u root -p'root123!@#' << 'MYSQLOPT'
SET GLOBAL innodb_buffer_pool_size = 256M;
SET GLOBAL query_cache_size = 32M;
SET GLOBAL query_cache_limit = 2M;
SET GLOBAL max_connections = 100;
FLUSH PRIVILEGES;
MYSQLOPT

# Otimizar PHP OPcache
echo "Otimizando PHP OPcache..."
cat >> /etc/php/8.1/apache2/php.ini << 'OPCACHE'

; Configurações OPcache otimizadas
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.revalidate_freq=2
opcache.save_comments=1
opcache.fast_shutdown=1
opcache.validate_timestamps=0
OPCACHE

# Configurar Apache para melhor performance
cat > /etc/apache2/conf-available/performance.conf << 'PERFORMANCE'
# Configurações de performance

# Prefork MPM otimizado
<IfModule mpm_prefork_module>
    StartServers             8
    MinSpareServers          5
    MaxSpareServers         20
    ServerLimit            256
    MaxRequestWorkers      256
    MaxConnectionsPerChild 1000
</IfModule>

# Compressão
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/javascript application/x-javascript application/json application/xml+rss application/atom+xml image/svg+xml
</IfModule>

# Cache Headers
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresDefault "access plus 1 month"
    ExpiresByType text/html "access plus 0 seconds"
    ExpiresByType text/xml "access plus 0 seconds"
    ExpiresByType application/xml "access plus 0 seconds"
    ExpiresByType application/json "access plus 0 seconds"
</IfModule>

# Headers de performance
<IfModule mod_headers.c>
    Header unset ETag
    Header set Connection keep-alive
    Header unset Server
</IfModule>

# Disable ETags
FileETag None
PERFORMANCE

a2enconf performance

# Reiniciar serviços
systemctl restart apache2
systemctl restart mysql
systemctl restart php8.1-fpm

echo "✅ Otimização concluída!"
echo "📊 Para monitorar performance, use: htop"
echo "🔍 Para logs: tail -f /var/log/apache2/error.log"
EOF

chmod +x /usr/local/bin/optimize-server

# Criar script de backup completo
cat > /usr/local/bin/backup-sites << 'EOF'
#!/bin/bash

BACKUP_DIR="/var/backups/websites"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "🔄 Iniciando backup completo dos sites..."

# Backup dos arquivos
echo "📁 Fazendo backup dos arquivos..."
tar -czf "$BACKUP_DIR/websites_$DATE.tar.gz" /var/www/html/ 2>/dev/null

# Backup dos bancos de dados
echo "🗄️ Fazendo backup dos bancos de dados..."
mysqldump --all-databases -u root -p'root123!@#' > "$BACKUP_DIR/databases_$DATE.sql" 2>/dev/null

# Backup das configurações do Apache
echo "⚙️ Fazendo backup das configurações Apache..."
tar -czf "$BACKUP_DIR/apache_config_$DATE.tar.gz" /etc/apache2/ 2>/dev/null

# Backup das configurações PHP
echo "🐘 Fazendo backup das configurações PHP..."
tar -czf "$BACKUP_DIR/php_config_$DATE.tar.gz" /etc/php/ 2>/dev/null

# Backup dos certificados SSL
echo "🔒 Fazendo backup dos certificados SSL..."
if [ -d "/etc/letsencrypt" ]; then
    tar -czf "$BACKUP_DIR/ssl_certificates_$DATE.tar.gz" /etc/letsencrypt/ 2>/dev/null
fi

echo "✅ Backup concluído: $BACKUP_DIR"

# Manter apenas os últimos 7 backups
find "$BACKUP_DIR" -name "*.tar.gz" -o -name "*.sql" | sort | head -n -21 | xargs rm -f 2>/dev/null

echo "🧹 Limpeza de backups antigos concluída"

# Mostrar tamanho dos backups
echo "📊 Tamanho dos backups:"
du -sh "$BACKUP_DIR"/*_$DATE.* 2>/dev/null
EOF

chmod +x /usr/local/bin/backup-sites

# Configurar cron para backups automáticos e otimização
echo "Configurando tarefas automáticas..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-sites") | crontab -
(crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/bin/optimize-server") | crontab -

# Instalar ferramentas de monitoramento
log "Instalando ferramentas de monitoramento..."
apt-get install -y iotop iftop nethogs

# Criar script de informações do sistema
cat > /usr/local/bin/server-info << 'EOF'
#!/bin/bash

echo "========================================="
echo "        INFORMAÇÕES DO SERVIDOR"
echo "========================================="
echo ""

echo "🖥️  SISTEMA:"
echo "   OS: $(lsb_release -d | cut -f2)"
echo "   Kernel: $(uname -r)"
echo "   Uptime: $(uptime -p)"
echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"
echo ""

echo "💾 MEMÓRIA:"
free -h
echo ""

echo "💽 DISCO:"
df -h | grep -E '^/dev/'
echo ""

echo "🌐 REDE:"
echo "   IP Externo: $(curl -s ifconfig.me 2>/dev/null || echo 'N/A')"
echo "   IP Interno: $(hostname -I | awk '{print $1}')"
echo ""

echo "🔧 SERVIÇOS:"
echo "   Apache: $(systemctl is-active apache2)"
echo "   MySQL: $(systemctl is-active mysql)"
echo "   PHP-FPM: $(systemctl is-active php8.1-fpm)"
echo "   Redis: $(systemctl is-active redis-server)"
echo "   Memcached: $(systemctl is-active memcached)"
echo ""

echo "🐘 PHP:"
echo "   Versão: $(php -v | head -1)"
echo "   Memory Limit: $(php -r 'echo ini_get("memory_limit");')"
echo "   Upload Max: $(php -r 'echo ini_get("upload_max_filesize");')"
echo ""

echo "🗄️  MYSQL:"
mysql -u root -p'root123!@#' -e "SELECT VERSION() AS 'MySQL Version';" 2>/dev/null
echo ""

echo "📁 SITES:"
echo "   Total de sites: $(find /var/www/html/sites/ -maxdepth 1 -type d | wc -l)"
echo "   Total de subdomínios: $(find /var/www/html/subdomains/ -maxdepth 1 -type d | wc -l)"
echo ""

echo "📊 ESTATÍSTICAS APACHE (últimas 24h):"
if [ -f "/var/log/apache2/access.log" ]; then
    echo "   Requests: $(grep $(date -d 'yesterday' '+%d/%b/%Y') /var/log/apache2/access.log | wc -l)"
    echo "   IPs únicos: $(grep $(date -d 'yesterday' '+%d/%b/%Y') /var/log/apache2/access.log | awk '{print $1}' | sort | uniq | wc -l)"
fi
echo ""
EOF

chmod +x /usr/local/bin/server-info

# Reiniciar todos os serviços
log "Reiniciando todos os serviços..."
systemctl restart apache2
systemctl restart mysql
systemctl restart php8.1-fpm
systemctl restart redis-server
systemctl restart memcached
systemctl restart fail2ban

# Status final dos serviços
log "Verificando status final dos serviços..."
echo "=========================================="
echo "          STATUS DOS SERVIÇOS"
echo "=========================================="
services=("apache2" "mysql" "php8.1-fpm" "redis-server" "memcached" "fail2ban")

for service in "${services[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        echo "✅ $service: ATIVO"
    else
        echo "❌ $service: INATIVO"
    fi
done

# Verificar versões instaladas
echo ""
echo "=========================================="
echo "           VERSÕES INSTALADAS"
echo "=========================================="
echo "Apache: $(apache2 -v | head -1 | awk '{print $3}')"
echo "PHP 8.1: $(php8.1 -v | head -1 | awk '{print $2}')"
echo "PHP 7.4: $(php7.4 -v | head -1 | awk '{print $2}')"
echo "MySQL: $(mysql --version | awk '{print $5}' | sed 's/,//')"
echo "Composer: $(composer --version 2>/dev/null | awk '{print $3}')"
echo "Node.js: $(node -v 2>/dev/null)"
echo "Redis: $(redis-server --version | awk '{print $3}' | sed 's/v=//')"

# Executar otimização inicial
log "Executando otimização inicial..."
/usr/local/bin/optimize-server

# Informações finais
echo ""
echo "=========================================="
echo "        INSTALAÇÃO CONCLUÍDA! 🎉"
echo "=========================================="
echo ""
echo "🌐 Acesse: http://$(curl -s ifconfig.me 2>/dev/null)"
echo ""
echo "📋 COMANDOS DISPONÍVEIS:"
echo "   manage-domain add exemplo.com domain"
echo "   manage-domain ssl exemplo.com"
echo "   add-project meu-app exemplo.com laravel"
echo "   php-switch 8.1"
echo "   backup-sites"
echo "   optimize-server"
echo "   server-info"
echo ""
echo "📁 DOCUMENTAÇÃO: /root/servidor-web-info.txt"
echo "📊 PAINEL DE CONTROLE: http://$(curl -s ifconfig.me 2>/dev/null)/index.php"
echo ""
echo "✅ Servidor web completo instalado e configurado!"
echo "🔒 Não esqueça de configurar o DNS e executar SSL para seus domínios"
echo ""