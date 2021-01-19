{{Lowercase title}}
[[Category:Web server (Русский)]]
[[de:Nginx]]
[[en:Nginx]]
[[ja:Nginx]]
[[zh-hans:Nginx]]
{{TranslationStatus (Русский)|nginx|2015-07-29|388788}}

'''[[Wikipedia:ru:nginx|nginx]]''' (произносится "э́нжин-э́кс" или "э́нжин-и́кс") — это свободный высокопроизводительный HTTP-сервер с открытым исходным кодом, а также обратный прокси и IMAP/POP3 прокси-сервер, написанный Игорем Сысоевым в 2005 году. Согласно [http://news.netcraft.com/archives/2015/04/20/april-2015-web-server-survey.html April 2015 Web Server Survey], nginx используется на 14,48% доменов всего мира, в то время как [[Apache HTTP Server (Русский)|Apache]] используется примерно на 38,39% доменов. nginx получил широкое распространение благодаря своей стабильности, богатой функциональности, простой настройке и низкому потреблению ресурсов.

== Установка ==

[[Установите]] пакет {{Pkg|nginx}}.

Для установки Ruby on Rails с nginx смотрите раздел [[Ruby on Rails#The Perfect Rails Setup]].

Если для обеспечения дополнительной безопасности вы хотите установить nginx в chroot-окружении, смотрите раздел [[#Установка в chroot]].

== Запуск ==

Запустите/включите {{ic|nginx.service}} [[systemd (Русский)#Использование юнитов|используя systemd]].

Страница по умолчанию, доступная по адресу http://127.0.0.1 располагается в {{ic|/usr/share/nginx/html/index.html}}.

== Настройка ==

Первые шаги по настройке и использованию nginx описаны в руководстве [http://nginx.org/ru/docs/beginners_guide.html Beginner’s Guide]. Вы можете настроить сервер, редактируя файлы в {{ic|/etc/nginx/}}; главный файл настроек расположен в {{ic|/etc/nginx/nginx.conf}}.

Более подробную информацию можно прочитать на странице [http://wiki.nginx.org/Configuration Nginx Configuration Examples] и в [http://nginx.org/ru/docs/ официальной документации].

Приведенные далее примеры покрывают большинство типичных потребностей. Предполагается, что вы используете стандартное место расположения веб-документов ({{ic|/usr/share/nginx/html}}). Если это не так, замените путь на свой.

=== Основные настройки ===

==== Процессы и соединения ====

Вы должны выбрать подходящее значение для {{ic|worker_processes}}. Этот параметр определяет сколько одновременных соединений сможет принимать nginx и сколько процессоров он сможет при этом использовать. Как правило, это значение устанавливают равным количеству аппаратных потоков в системе. Однако, начиная с версий 1.3.8 и 1.2.5, в качестве значения {{ic|worker_processes}} вы также можете задать {{ic|auto}}, при этом nginx попытается автоматически подобрать оптимальное значение ([http://nginx.org/ru/docs/ngx_core_module.html#worker_processes источник]).

Максимальное количество одновременных соединений, которое nginx сможет принимать, вычисляется как {{ic|1=max_clients = worker_processes * worker_connections}}.

==== Запуск под другим пользователем ====

По умолчанию nginx выполняется от имени пользователя ''nobody''. Чтобы запустить его от имени другого пользователя, измените строку {{ic|user}} в {{ic|nginx.conf}}:

{{hc|/etc/nginx/nginx.conf|
user ''пользователь'' ''группа''; # например http
}}

Теперь Nginx должен работать от указанного имени пользователя ''пользователь'' и группы ''группа''. Если используется группа, имя которой совпадает с именем пользователя, то ее название можно опустить.

==== Блоки server ====

Посредством добавления блоков {{ic|server}} в файл настроек возможно обслуживать сразу несколько доменов одновременно. Эти блоки работают аналогично "VirtualHosts" в [[Apache HTTP Server (Русский)|Apache]].

В этом примере сервер принимает запросы для двух доменов: {{ic|domainname1.dom}} и {{ic|domainname2.dom}}:

{{hc|/etc/nginx/nginx.conf|<nowiki>
...
server {
        listen 80;
        server_name domainname1.dom;
        root /usr/share/nginx/domainname1.dom/html;
        ...
}

server {
        listen 80;
        server_name domainname2.dom;
        listen 443 ssl; # также прослушивать по HTTPS
        root /usr/share/nginx/domainname2.dom/html;
        ...
}
...
</nowiki>}}

[[Перезапустите]] службу {{ic|nginx}}, чтобы изменения вступили в силу.

Следует настроить DNS-сервер, например [[BIND]] или [[dnsmasq]], чтобы у подключающихся клиентов эти доменные имена разрешались в IP-адрес сервера.

А пока вы можете просто добавить их в ваш файл {{ic|/etc/hosts}}, заменив {{ic|192.168.0.101}} на фактический IP-адрес сервера:

 192.168.0.101 domainname1.dom
 192.168.0.101 domainname2.dom

==== TLS/SSL ====

{{pkg|openssl}} предоставляет поддержку TLS/SSL и установлен по умолчанию на установленных Arch.
{{Tip (Русский)|Перед тем как настраивать SSL, вы можете почитать документацию [http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_certificate ngx_http_ssl_module]}}

Создайте секретный ключ и самоподписанный сертификат. Это подходит для большинства случаев, в которых не требуется  [[wikipedia:Certificate_signing_request|CSR]]:

 # cd /etc/nginx/
 # openssl req -new -x509 -nodes -newkey rsa:4096 -keyout nginx.key -out nginx.crt -days 1095
 # chmod 400 nginx.key
 # chmod 444 nginx.crt

{{Note (Русский)| Опция -days является необязательной, а RSA keysize можно уменьшить до 2048 (по умолчанию).}}

Если же вам нужно создать [[wikipedia:Certificate_signing_request|CSR]], то следуйте данным инструкциям по созданию ключа, вместо приведённых выше:

 # openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out nginx.key
 # chmod 400 nginx.key
 # openssl req -new -sha256 -key nginx.key -out nginx.csr
 # openssl x509 -req -days 1095 -in nginx.csr -signkey nginx.key -out nginx.crt

{{Note (Русский)| Для дополнительных опций openssl, прочтите [https://www.openssl.org/docs/apps/openssl.html man страницу] или изучите [https://www.openssl.org/docs/ подробную документацию] по openssl.}}

{{Warning (Русский)|Если вы планируете развернуть SSL/TLS, вы должны знать, что некоторые вариации и реализации [https://weakdh.org/#affected всё ещё] [[wikipedia:Transport_Layer_Security#Attacks_against_TLS.2FSSL|подвержены атакам]]. За дополнительной информацией о текущих подверженных версиях этих реализаций  SSL/TLS и как применить нужные настройки к nginx посетите http://disablessl3.com/ и https://weakdh.org/sysadmin.html}}

Пример {{ic|nginx.conf}}, использующего SSL:

{{hc|/etc/nginx/nginx.conf|<nowiki>
http {
        ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.8.8 8.8.4.4 valid=300s; # Google DNS Servers
        resolver_timeout 5s;
}

server {
        #listen 80; # Раскомментируйте, чтобы также слушать HTTP запросы
        listen 443 ssl;
        server_name localhost;

        ssl_certificate nginx.crt;
        ssl_certificate_key nginx.key;

	root /usr/share/nginx/html;
        location / {
            index  index.html index.htm index.php;
        }
}</nowiki>}}

{{Tip (Русский)|У Mozilla есть полезная [https://wiki.mozilla.org/Security/Server_Side_TLS SSL/TLS статья], которая описывает рекомендации по настройке [https://wiki.mozilla.org/Security/Server_Side_TLS#Nginx специально для nginx], а также [https://mozilla.github.io/server-side-tls/ssl-config-generator/ автоматизированный инструмент], который поможет вам создать более безопасную конфигурацию.}}
{{Tip (Русский)|[https://cipherli.st Cipherli.st]{{Dead link (Русский)|2020|08|04|status=SSL error}} показывает примеры надёжных настроек SSL и инструкции для наиболее современных веб серверов.}}

[[Перезапустите]] службу {{ic|nginx}}, чтобы изменения вступили в силу.

=== FastCGI ===

FastCGI или просто FCGI — это протокол, являющийся интерфейсом между веб-сервером и интерактивными программами. Это модифицированный CGI (''Common Gateway Interface''), главная цель которого — снизить накладные расходы, связанные со взаимодействием веб сервера и CGI программ, тем самым позволяя серверу обрабатывать большее количество запросов одновременно.

Технология FastCGI встроена в nginx для работы со многими внешними инструментами, например, Perl, [[PHP]] и [[Python (Русский)|Python]].

==== Реализация PHP ====

В качестве FastCGI-сервера для PHP рекомендуется использовать [http://php-fpm.org/ PHP-FPM].

===== Настройка PHP =====

[[Установите]] пакеты {{Pkg|php}} и {{Pkg|php-fpm}}.

Опция {{ic|open_basedir}} в {{ic|/etc/php/php.ini}} должна содержать список всех каталогов, с файлами PHP, которые должны быть доступны серверу. Например, для {{ic|/usr/share/nginx/html/}} и {{ic|/usr/share/webapps/}}:

 open_basedir = /usr/share/webapps/:/srv/http/:/usr/share/nginx/html/:/home/:/tmp/:/usr/share/pear/

После этого настройте нужные вам модули. Например, для использования sqlite3 нужно установить {{Pkg|php-sqlite}}. Затем включите этот модуль в файле {{ic|/etc/php/php.ini}}, раскомментировав следующую строку:

 extension=sqlite3.so

Основным конфигурационным файлом PHP-FPM является {{ic|/etc/php/php-fpm.conf}}. [[Включите]] и [[запустите]] [[systemd (Русский)|systemd]] службу {{ic|php-fpm}}.

{{Note (Русский)|Если вы запускаете nginx в изолированном окружении (к примеру, chroot находится в {{ic|/srv/nginx-jail}}, веб-документы расположены в {{ic|/srv/nginx-jail/www}}), то вы должны в {{ic|/etc/php/php-fpm.conf}} добавить опции {{ic|chroot /srv/nginx-jail}} и {{ic|1=listen = /srv/nginx-jail/run/php-fpm/php-fpm.sock}} внутри секции пула (по умолчанию это {{ic|[www]}}). Создайте каталог для файла сокета, если его нет.}}

====== MariaDB ======

Настройте MySQL/MariaDB как описано в [[MariaDB]].

Раскомментируйте [http://www.php.net/manual/en/mysqlinfo.api.choosing.php хотя бы одну] из следующих строк в {{ic|/etc/php/php.ini}}:

 extension=pdo_mysql.so
 extension=mysqli.so

{{Warning (Русский)|Начиная с PHP 5.5, {{ic|mysql.so}} объявлен [http://www.php.net/manual/de/migration55.deprecated.php устаревшим], ваши лог файлы будут переполнены.}}

Вы можете добавить менее привилегированных MySQL пользователей для ваших веб скриптов. Вы можете также захотеть отредактировать {{ic|/etc/mysql/my.cnf}} и раскомментировать строку {{ic|skip-networking}}, чтобы MySQL сервер был доступен только из localhost. Вы должны перезапустить MySQL, чтобы изменения вступили в силу.

{{Tip (Русский)|Вы можете захотеть установить инструменты вроде [[phpMyAdmin]], [[Adminer]] или {{Pkg|mysql-workbench}}, чтобы работать с вашими базами данных.}}

===== Настройка nginx =====

====== Добавление к основной конфигурации ======

Внутри каждого блока {{ic|server}}, который обслуживает веб-приложение PHP должен находиться блок {{ic|location}}:

 location ~ \.php$ {
      fastcgi_pass   unix:/run/php-fpm/php-fpm.sock;
      fastcgi_index  index.php;
      include        fastcgi.conf;
 }

Если требуется обрабатывать другие расширения наряду с PHP (например ''.html'' и ''.htm''):

 location ~ \.(php'''|html|htm''')$ {
      fastcgi_pass   unix:/run/php-fpm/php-fpm.sock;
      fastcgi_index  index.php;
      include        fastcgi.conf;
 }

Все расширения, обрабатываемые в php-fpm должны быть также явно добавлены в
{{ic|/etc/php/php-fpm.conf}}:

 security.limit_extensions = .php .html .htm

{{Note (Русский)|Аргумент {{ic|fastcgi_pass}} должен быть определен как TCP-сокет или сокет Unix выбранным FastCGI сервером в его конфигурационном файле. '''По умолчанию''' для {{ic|php-fpm}} используется сокет

 fastcgi_pass unix:/run/php-fpm/php-fpm.sock;

Вы можете использовать также общий TCP-сокет:

 fastcgi_pass 127.0.0.1:9000;

Однако, доменные сокеты Unix должны работать быстрее.}}

Пример, показанный ниже, является копией рабочей конфигурации. Заметьте, что в этом примере путь к {{ic|root}} определен непосредственно в {{ic|server}}, а не внутри {{ic|location}} (как это сделано в конфигурации по умолчанию).

 server {
     listen 80;
     server_name localhost;
     root /usr/share/nginx/html;
     location / {
         index index.html index.htm index.php;
     }
 
     location ~ \.php$ {
         #fastcgi_pass 127.0.0.1:9000; (depending on your php-fpm socket configuration)
         fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
         fastcgi_index index.php;
         include fastcgi.conf;
     }
 }

====== Управление несколькими блоками (опционально) ======

Если вы добавляете однотипную конфигурацию для PHP сразу во множество блоков {{ic|server}}, может оказаться удобнее использовать для этого внешний файл:

{{hc|/etc/nginx/php.conf|<nowiki>
location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/php-fpm.sock;
        fastcgi_index index.php;
        include fastcgi.conf;
}
</nowiki>}}

Теперь включите файл {{ic|php.conf}} в каждый из блоков {{ic|server}}:

{{hc|/etc/nginx/nginx.conf|<nowiki>
 server = {
     ...
     include php.conf;
 }
</nowiki>}}

===== Проверка конфигурации =====

[[Перезапустите]] службы {{ic|php-fpm}} и {{ic|nginx}} после изменения настроек, чтобы изменения вступили в силу.

Чтобы проверить работу FastCGI, создайте новый файл ''.php'' внутри каталога веб-документов, содержащий:

 <?php
   phpinfo();
 ?>

При открытии файла в браузере должна отобразиться информационная страница с текущими настройками PHP.

Смотрите [[#Решение проблем]], если новая конфигурация не работает.

==== Реализация CGI ====

Эта реализация нужна для CGI-приложений.

===== fcgiwrap =====

[[Установите]] {{Pkg|fcgiwrap}}. Файл настроек находится в {{ic|/usr/lib/systemd/system/fcgiwrap.socket}}. [[Включите]] и [[запустите]] {{ic|fcgiwrap.socket}}.

====== Несколько рабочих потоков ======

Если вы хотите породить несколько рабочих потоков, вам рекомендуется использовать {{AUR|multiwatch}}, который умеет отслеживать упавшие подпроцессы и перезапускать их. Вам нужно использовать {{ic|spawn-fcgi}}, чтобы создать доменный сокет Unix, так как multiwatch не может обрабатывать сокеты, созданные [[systemd (Русский)|systemd]], однако, ''fcgiwrap'' сама по себе не вызывает никаких проблем, если вызывается непосредственно из юнит-файла.

Скопируйте юнит-файл из {{ic|/usr/lib/systemd/system/fcgiwrap.service}} в {{ic|/etc/systemd/system/fcgiwrap.service}} (и юнит {{ic|fcgiwrap.socket}}, если он есть), и отредактируйте строку {{ic|ExecStart}} в соответствии с вашими нуждами. В примере показан юнит файл, который использует {{AUR|multiwatch}}. Убедитесь, что {{ic|fcgiwrap.socket}} не включен и не запущен, потому что он будет конфликтовать с этим юнитом:

{{hc|/etc/systemd/system/fcgiwrap.service|2=
[Unit]
Description=Simple CGI Server
After=nss-user-lookup.target

[Service]
ExecStartPre=/bin/rm -f /run/fcgiwrap.socket
ExecStart=/usr/bin/spawn-fcgi -u http -g http -s /run/fcgiwrap.sock -n -- /usr/bin/multiwatch -f 10 -- /usr/sbin/fcgiwrap
ExecStartPost=/usr/bin/chmod 660 /run/fcgiwrap.sock
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
}}

Выберите подходящий {{ic|-f 10}}, чтобы изменить количество порождаемых подпроцессов.

{{Warning (Русский)|Строка {{ic|ExecStartPost}} требуется из-за странного поведения, которое я наблюдаю при использовании опции {{ic|-M 660}} для {{ic|spawn-fcgi}}. Устанавливается неправильный режим. Может это баг?}}

===== Настройка nginx =====

Внутри каждого блока {{ic|server}} CGI-приложения должен находиться вложенный блок {{ic|location}}:

  location ~ \.cgi$ {
       root           /path/to/server/cgi-bin;
       fastcgi_pass   unix:/run/fcgiwrap.sock;
       include        fastcgi.conf;
  }

Стандартным сокетом для {{ic|fcgiwrap}} является {{ic|/run/fcgiwrap.sock}}.

== Установка в chroot ==

Установка nginx в [[Change root (Русский)|chroot]] добавляет дополнительный уровень безопасности. Для максимальной безопасности chroot должен включать только файлы, необходимые для запуска сервера nginx, при этом все файлы должны иметь по возможности максимально ограниченные права доступа. Например, как можно больше файлов должно принадлежать пользователю root, а таким каталогам, как {{ic|/usr/bin}} должен быть установлен запрет на чтение и запись.

Arch поставляется с пользователем {{ic|http}} и группой по умолчанию, от имени которых запускается сервер. Измененный корневой каталог будет находиться в {{ic|/srv/http}}.

Существует perl-скрипт для создания chroot-окружения, который доступен в [https://gist.github.com/4365696 jail.pl gist]. Вы можете либо использовать его, либо следовать дальнейшим инструкциям из этой статьи. Скрипт требует прав суперпользователя для работы. Вам нужно будет раскомментировать строку, перед тем, как он сможет выполнять какие-либо изменения.

=== Создание необходимых устройств ===

Для nginx нужны {{ic|/dev/null}}, {{ic|/dev/random}} и {{ic|/dev/urandom}}. Чтобы установить их в chroot мы создадим каталог {{ic|/dev}} и добавим устройства с помощью ''mknod''. Избегайте монтирования всех устройств в {{ic|/dev}}: тогда, даже если chroot будет скомпрометирован, атакующий должен будет выбраться из chroot-окружения чтобы добраться до важных устройств, например {{ic|/dev/sda1}}.
{{Tip (Русский)|Убедитесь, что {{ic|/src/http}} примонтирован без опции no-dev}}
{{Tip (Русский)|Смотрите {{man|1|mknod}} и {{ic|<nowiki>ls -l /dev/{null,random,urandom}</nowiki>}}, чтобы лучше понять опции ''mknod''.}}

 # export JAIL=/srv/http
 # mkdir $JAIL/dev
 # mknod -m 0666 $JAIL/dev/null c 1 3
 # mknod -m 0666 $JAIL/dev/random c 1 8
 # mknod -m 0444 $JAIL/dev/urandom c 1 9

=== Создание необходимых каталогов ===

Для работы nginx требует определенный набор файлов. Перед тем, как их копировать, создайте для них соответствующие каталоги. Предполагается, что ваш корневой каталог веб-документов nginx находится в {{ic|/srv/http/www}}.

 # mkdir -p $JAIL/etc/nginx/logs
 # mkdir -p $JAIL/usr/{lib,bin}
 # mkdir -p $JAIL/usr/share/nginx
 # mkdir -p $JAIL/var/{log,lib}/nginx
 # mkdir -p $JAIL/www/cgi-bin
 # mkdir -p $JAIL/{run,tmp}
 # cd $JAIL; ln -s usr/lib lib

{{Note (Русский)|Если вы используете 64-битное ядро, вам нужно создать символические ссылки для {{ic|lib64}} и {{ic|usr/lib64}} в {{ic|usr/lib}}: {{ic|cd $JAIL; ln -s usr/lib lib64}} и {{ic|cd $JAIL/usr; ln -s lib lib64}}.}}

Затем смонтируйте {{ic|$JAIL/tmp}} и {{ic|$JAIL/run}} как tmpfs-ы. Размер должен быть ограничен, чтобы быть уверенным, что атакующий не сможет занять всю доступную RAM.

 # mount -t tmpfs none $JAIL/run -o 'noexec,size=1M'
 # mount -t tmpfs none $JAIL/tmp -o 'noexec,size=100M'

Для того, чтобы монтирование выполнялось автоматически при загрузке системы, добавьте следующие записи в {{ic|/etc/fstab}}:

{{hc|/etc/fstab|<nowiki>
 tmpfs   /srv/http/run   tmpfs   rw,noexec,relatime,size=1024k   0       0
 tmpfs   /srv/http/tmp   tmpfs   rw,noexec,relatime,size=102400k 0       0
</nowiki>}}

=== Заполнение chroot ===

Сначала скопируйте простые файлы.

 # cp -r /usr/share/nginx/* $JAIL/usr/share/nginx
 # cp -r /usr/share/nginx/html/* $JAIL/www
 # cp /usr/bin/nginx $JAIL/usr/bin/
 # cp -r /var/lib/nginx $JAIL/var/lib/nginx

Теперь скопируйте нужные библиотеки. Используйте ''ldd'', чтобы отобразить их и скопируйте все файлы в правильное место. Копирование предпочтительнее, чем создание жестких ссылок, потому, что даже если атакующий получит права записи в файлы, они не смогут уничтожить или изменить системные файлы вне chroot-окружения.

{{hc|$ ldd /usr/bin/nginx|<nowiki>
linux-vdso.so.1 (0x00007fffc41fe000)
libpthread.so.0 => /usr/lib/libpthread.so.0 (0x00007f57ec3e8000)
libcrypt.so.1 => /usr/lib/libcrypt.so.1 (0x00007f57ec1b1000)
libstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x00007f57ebead000)
libm.so.6 => /usr/lib/libm.so.6 (0x00007f57ebbaf000)
libpcre.so.1 => /usr/lib/libpcre.so.1 (0x00007f57eb94c000)
libssl.so.1.0.0 => /usr/lib/libssl.so.1.0.0 (0x00007f57eb6e0000)
libcrypto.so.1.0.0 => /usr/lib/libcrypto.so.1.0.0 (0x00007f57eb2d6000)
libdl.so.2 => /usr/lib/libdl.so.2 (0x00007f57eb0d2000)
libz.so.1 => /usr/lib/libz.so.1 (0x00007f57eaebc000)
libGeoIP.so.1 => /usr/lib/libGeoIP.so.1 (0x00007f57eac8d000)
libgcc_s.so.1 => /usr/lib/libgcc_s.so.1 (0x00007f57eaa77000)
libc.so.6 => /usr/lib/libc.so.6 (0x00007f57ea6ca000)
/lib64/ld-linux-x86-64.so.2 (0x00007f57ec604000)</nowiki>}}

 # cp /lib64/ld-linux-x86-64.so.2 $JAIL/lib

Для файлов, находящихся в {{ic|/usr/lib}}, вы можете воспользоваться следующей командой:

 # cp $(ldd /usr/bin/nginx | grep /usr/lib | sed -sre 's/(.+)(\/usr\/lib\/\S+).+/\2/g') $JAIL/usr/lib

{{Note (Русский)|Не пытайтесь скопировать {{ic|linux-vdso.so}} — это не настоящая библиотека и ее не существует в {{ic|/usr/lib}}. Аналогично {{ic|ld-linux-x86-64.so}} также будет отображена в {{ic|/lib64}} для 64-битной системы.}}

Копируйте другие необходимые библиотеки и системные файлы.

 # cp /usr/lib/libnss_* $JAIL/usr/lib
 # cp -rfvL /etc/{services,localtime,nsswitch.conf,nscd.conf,protocols,hosts,ld.so.cache,ld.so.conf,resolv.conf,host.conf,nginx} $JAIL/etc

Создайте файлы пользователей и групп в chroot-окружении. Таким образом, в chroot-окружении будут доступны только указанные пользователи, и никакая информация о пользователях из основной системы не будет доступна атакующему, получившему доступ в chroot-окружение.

{{hc|$JAIL/etc/group|
http:x:33:
nobody:x:99:
}}

{{hc|$JAIL/etc/passwd|
http:x:33:33:http:/:/bin/false
nobody:x:99:99:nobody:/:/bin/false
}}

{{hc|$JAIL/etc/shadow|
http:x:14871::::::
nobody:x:14871::::::
}}

{{hc|$JAIL/etc/gshadow|
http:::
nobody:::
}}

 # touch $JAIL/etc/shells
 # touch $JAIL/run/nginx.pid

Наконец, сделайте права доступа максимально ограниченными. Как можно больше должно принадлежать суперпользователю и быть закрытым для записи.

 # chown -R root:root $JAIL/
 
 # chown -R http:http $JAIL/www
 # chown -R http:http $JAIL/etc/nginx
 # chown -R http:http $JAIL/var/{log,lib}/nginx
 # chown http:http $JAIL/run/nginx.pid
 
 # find $JAIL/ -gid 0 -uid 0 -type d -print | xargs sudo chmod -rw
 # find $JAIL/ -gid 0 -uid 0 -type d -print | xargs sudo chmod +x
 # find $JAIL/etc -gid 0 -uid 0 -type f -print | xargs sudo chmod -x
 # find $JAIL/usr/bin -type f -print | xargs sudo chmod ug+rx
 # find $JAIL/ -group http -user http -print | xargs sudo chmod o-rwx
 # chmod +rw $JAIL/tmp
 # chmod +rw $JAIL/run

Если ваш сервер будет принимать входящие соединения на 80 порту (или любому другому порту в диапазоне [1-1023]), дайте исполнителю chroot права на соединение с этими портами без необходимости прав суперпользователя.

 # setcap 'cap_net_bind_service=+ep' $JAIL/usr/bin/nginx

=== Отредактируйте nginx.service для запуска chroot ===

Перед редактированием юнит-файла {{ic|nginx.service}} неплохо будет скопировать его в {{ic|/etc/systemd/system/}}, так как там юнит файлы имеют приоритет над теми, что в {{ic|/usr/lib/systemd/system/}}. Это значит, что обновление nginx не перезапишет ваш собственный файл ''.service''.

 # cp /usr/lib/systemd/system/nginx.service /etc/systemd/system/nginx.service

Юнит systemd должен быть настроен так, чтобы запускать nginx в chroot от имени пользователя http и хранить pid-файл в chroot.

{{Note (Русский)|Я не уверен, нужно ли хранить pid-файл в chroot.}}

{{hc|/etc/systemd/system/nginx.service|<nowiki>
 [Unit]
 Description=A high performance web server and a reverse proxy server
 After=syslog.target network.target
 
 [Service]
 Type=forking
 PIDFile=/srv/http/run/nginx.pid
 ExecStartPre=/usr/bin/chroot --userspec=http:http /srv/http /usr/bin/nginx -t -q -g 'pid /run/nginx.pid; daemon on; master_process on;'
 ExecStart=/usr/bin/chroot --userspec=http:http /srv/http /usr/bin/nginx -g 'pid /run/nginx.pid; daemon on; master_process on;'
 ExecReload=/usr/bin/chroot --userspec=http:http /srv/http /usr/bin/nginx -g 'pid /run/nginx.pid; daemon on; master_process on;' -s reload
 ExecStop=/usr/bin/chroot --userspec=http:http /srv/http /usr/bin/nginx -g 'pid /run/nginx.pid;' -s quit
 
 [Install]
 WantedBy=multi-user.target</nowiki>}}

{{Note (Русский)|Обновление nginx с помощью pacman не обновит установленную в chroot копию. Вы должны вручную выполнять обновления, повторяя указанные выше шаги по переносу файлов. Не забудьте также обновить библиотеки, которые использует nginx.}}

Теперь вы можете спокойно удалить установленный вне chroot nginx.

 # pacman -Rsc nginx

Если вы не удалили установленный вне chroot nginx, проверьте, что работающий процесс nginx — это действительно именно тот, что в находится chroot. Для этого посмотрите, куда указывает символическая ссылка {{ic|/proc/{PID}/root}}: она должен указывать на {{ic|/srv/http}}, а не на {{ic|/}}.

 # ps -C nginx | awk '{print $1}' | sed 1d | while read -r PID; do ls -l /proc/$PID/root; done

== Решение проблем ==

=== Валидация конфигурации  ===

 # nginx -t

 nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
 nginx: configuration file /etc/nginx/nginx.conf test is successful

=== При доступе с локального IP перенаправляется на localhost ===

Решение с [https://bbs.archlinux.org/viewtopic.php?pid=780561#p780561 форума Arch Linux].

В файле {{ic|/etc/nginx/nginx.conf}} найдите незакомментированную строку {{ic|server_name localhost}} (без {{ic|#}} вначале) и добавьте под ней:

 server_name_in_redirect off;

По умолчанию, nginx перенаправляет любые запросы на указанное в опции {{ic|server_name}} имя.

=== Ошибка: Страница, которую вы ищите, временно недоступна. Пожалуйста, попробуйте позже. (502 Bad Gateway) ===

Это из-за того, что сервер FastCGI не запущен или используемый сокет имеет неправильные права доступа.

Попробуйте [https://stackoverflow.com/questions/4252368/nginx-502-bad-gateway/16497957#16497957 этот ответ], чтобы исправить 502 ошибку.

В Archlinux, файлом настройки, упомянутом по ссылке выше, является {{ic|/etc/php/php-fpm.conf}}.

При определённых обстоятельствах, {{ic|fcgiwrap.socket}} может не запуститься правильно и создать бесполезный сокет юникс домена {{ic|/run/fcgiwrap.sock}}.

Попробуйте [[остановить]] службу {{ic|fcgiwrap.socket}} и удалить файл доменного юникс сокета по умолчанию.
 {{ic|# rm /run/fcgiwrap.sock}}
Затем [[запустите]] {{ic|fcgiwrap.service}} вместо него.
Проверьте статус {{ic|fcgiwrap.service}} и нового доменного юникс сокета {{ic|/run/fcgiwrap.sock}}:
 {{bc|$ systemctl status fcgiwrap.service
$ ls /run/fcgiwrap.sock}}
Если это сработало, [[отключите]] {{ic|fcgiwrap.socket}} и [[включите]] {{ic|fcgiwrap.service}}.

=== Ошибка: No input file specified ===

1. Скорее всего у вас не установлена переменная {{ic|SCRIPT_FILENAME}}, содержащая полный путь до ваших скриптов. Если конфигурация nginx ({{ic|fastcgi_param SCRIPT_FILENAME}}) правильная, то эта ошибка означает, что php не смог загрузить запрашиваемый скрипт. Часто это просто оказывается ошибкой прав доступа, и вы можете запустить php-cgi с правами root:

 # spawn-fcgi -a 127.0.0.1 -p 9000 -f /usr/bin/php-cgi

или вам следует создать группу и пользователя для запуска php-cgi:

 # groupadd www
 # useradd -g www www
 # chmod +w /srv/www/nginx/html
 # chown -R www:www /srv/www/nginx/html
 # spawn-fcgi -a 127.0.0.1 -p 9000 -u www -g www -f /usr/bin/php-cgi

2. Другой причиной может быть то, что задан неправильный аргумент {{ic|root}} в секции {{ic|location ~ \.php$}} в {{ic|nginx.conf}}. Убедитесь, что {{ic|root}} указывает на ту же директорию, что и в {{ic|location /}} на том же сервере. Либо вы можете просто задать абсолютный путь до корневого каталога, не определяя его в каких-либо location секциях.

3. Убедитесь, что переменная {{ic|open_basedir}} в {{ic|/etc/php/php.ini}} также содержит путь, который соответствует аргументу {{ic|root}} в {{ic|nginx.conf}}.

4. Также обратите внимание, что не только php-скрипты должны иметь права на чтение, но также и вся структура каталогов должна иметь право на исполнение, чтобы пользователь PHP мог добраться до этого каталога.

=== Ошибка: "File not found" в браузере или "Primary script unknown" в лог-файле ===

Убедитесь, что вы определили {{ic|root}} и {{ic|index}} в ваших директивах {{ic|server}} или {{ic|location}}:

  location ~ \.php$ {
       root           /srv/http/root_dir;
       index          index.php;
       fastcgi_pass   unix:/run/php-fpm/php-fpm.sock;
       include        fastcgi.conf;
  }

Также убедитесь, что запрашиваемый файл существует на сервере.

=== Ошибка: chroot: '/usr/sbin/nginx' No such file or directory ===

Если у вас возникает эта ошибка при запуске демона ''nginx'' в chroot, скорее всего, это происходит из-за отсутствующих 64-битных библиотек в изолированном окружении.

Если ваш chroot запущен в {{ic|/srv/http}}, вам нужно добавить требуемые 64-битные библиотеки.

Сначала создайте каталоги:

 # mkdir /srv/http/usr/lib64
 # cd /srv/http; ln -s usr/lib64 lib64

Затем скопируйте требуемые 64-битные библиотеки, перечисленные командой {{ic|ldd /usr/sbin/nginx}} в {{ic|/srv/http/usr/lib64}}.

При запуске от root, на библиотеки должны быть права чтения и исполнения для всех пользователей, так что изменения не требуются.

=== Альтернативный скрипт для systemd ===

На чистой systemd вы можете получить преимущества при использовании связки chroot и systemd [http://0pointer.de/blog/projects/changing-roots.html]. На основе заданных [http://wiki.nginx.org/CoreModule#user пользователя и группы] и pid:

{{hc|/etc/nginx/nginx.conf|2=
user http;
pid /run/nginx.pid;
}}

абсолютным путем к файлу является {{ic|/srv/http/etc/nginx/nginx.conf}}.3

{{hc|/etc/systemd/system/nginx.service|2=
[Unit]
Description=nginx (Chroot)
After=syslog.target network.target

[Service]
Type=forking
PIDFile=/srv/http/run/nginx.pid
RootDirectory=/srv/http
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -c /etc/nginx/nginx.conf -s reload
ExecStop=/usr/sbin/nginx -c /etc/nginx/nginx.conf -s stop

[Install]
WantedBy=multi-user.target
}}

Нет необходимости задавать расположение по умолчанию, nginx по умолчанию загружает {{ic| -c /etc/nginx/nginx.conf}}, хотя вообще это хорошая идея.

Также можно запускать '''только''' {{ic|ExecStart}} как chroot с параметром {{ic|RootDirectoryStartOnly}} заданным как {{ic|yes}} [https://www.freedesktop.org/software/systemd/man/systemd.service.html man systemd service] или запустить его до точки монтирования в качестве эффективного или [https://www.freedesktop.org/software/systemd/man/systemd.path.html пути systemd].

{{hc|/etc/systemd/system/nginx.path|2=
[Unit]
Description=nginx (Chroot) path
[Path]
PathExists=/srv/http/site/Public_html
[Install]
WantedBy=default.target
}}

[[Включите]] {{ic|nginx.path}} и замените {{ic|1=WantedBy=default.target}} на {{ic|1=WantedBy=nginx.path}} in {{ic|/etc/systemd/system/nginx.service}}.

Ссылка {{ic|PIDFile}} в файле юнита позволяет systemd следить за процессом (необходим абсолютный путь). Если это нежелательно, вы можете изменить тип one-shoot по умолчанию и удалить ссылку из файла юнита.

== Смотрите также ==

* [https://calomel.org/nginx.html Very good in-depth 2014 look at Nginx security and Reverse Proxying]
* [http://nginx.org/ Nginx Official Site]
* [http://calomel.org/nginx.html Nginx HowTo]
* [http://blog.gotux.net/tutorial/custom-nginx-indexer/ Custom Nginx Indexer]{{Dead link (Русский)|2020|08|04|status=domain name not resolved}}
* [http://www.tecmint.com/install-nginx-php-mysql-with-mariadb-engine-and-phpmyadmin-in-arch-linux/ Installing LEMP (Nginx, PHP, MySQL with MariaDB engine and PhpMyAdmin) in Arch Linux]
