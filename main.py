# A set of tools for testing Minecraft servers for vulnerabilities.
# Developed by vadiscode.
import re
from time import sleep

from telegram import Update, ParseMode, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, CallbackContext

import socket
import nmap
from mcstatus import MinecraftServer

def init(token):
    try:
        updater = Updater(token)

        updater.dispatcher.add_handler(CommandHandler('help', help))
        updater.dispatcher.add_handler(CommandHandler('info', info))
        updater.dispatcher.add_handler(CommandHandler('range', range))
        updater.dispatcher.add_handler(CommandHandler('subdomains', subdomains))
        updater.dispatcher.add_handler(CommandHandler("scan", scan))

        updater.start_polling()
        updater.idle()
    except:
        print('Failed to initialize main code.')

def help(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('ℹ Find out information about the server >>> /info <Server IP> ℹ\n\n📡 Scan server for ports >>> /scan <Server IP> <Speed (1-10)> <Port Range(x-x)> 📡\n\n📟 Search server subdomains /subdomains <Server IP> 📟\n\n🩺 Search with IP Range /range <Server IP> <Port Range> (Use 25565 for Bungee Search) 🩺')

def info(update: Update, context: CallbackContext) -> None:
    try:
        text = context.args[0]
        if ':' in text:
            address = text.split(':')[0]
            addressport = text.split(':')[1]
            server = MinecraftServer(address, port=int(addressport))
        else:
            address = text
            server = MinecraftServer.lookup(address)
        status = server.status()

        bad_chars = ['§0', '§1', '§2', '§3', '§4', '§5', '§6', '§7', '§8', '§9', '§a', '§b', '§c', '§d', '§e', '§f',
                     '§g', '§k', '§l', '§m', '§n', '§o', '§r']

        print('Nigger: ' + socket.gethostbyname(server.host) + ':' + str(server.port))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((socket.gethostbyname(server.host), int(server.port)))
        s.send(b'\xfe\x01')
        data = s.recv(1024)[3:].decode("utf-16be")[3:].split("\x00")
        s.close()
        motd = re.sub(r'ยง[a-zA-Z0-9]', '', data[2].strip().replace('  ', '').replace('  ', ''))

        try:
            for i in bad_chars:
                motd = motd.replace(i, '')
        except AttributeError:
            motd = motd

        update.message.reply_text(
            '*⇨ IP Address:* {0} ({1}:{2})\n*⇨ Status:* 🟢\n*⇨ Players:* ({3}/{4})\n*⇨ Version:* {5} | Protocol {6}\n*⇨ MOTD:* {7}'.format(
                address,
                socket.gethostbyname(server.host),
                server.port,
                status.players.online,
                status.players.max,
                str(status.version.name).lstrip(),
                str(status.version.protocol).lstrip(),
                str(motd).lstrip()
            ), parse_mode=ParseMode.MARKDOWN
        )
    except:
        if ':' in text:
            address = text.split(':')[0]
            addressport = text.split(':')[1]
            update.message.reply_text(
                '*⇨ IP Address:* {0}:{1}\n*⇨ Status:* 🔴'.format(
                    address,
                    addressport
                ), parse_mode=ParseMode.MARKDOWN
            )
        else:
            update.message.reply_text(
                '*⇨ IP Address:* {0}\n*⇨ Status:* 🔴'.format(
                    address
                ), parse_mode=ParseMode.MARKDOWN
            )
        pass

def subdomains(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('🟡 Search started 🟡')
    try:
        subdomains = ['www', 'torneoyt', 'hcf', 'uhc5', 'uhc4', 'uhc3', 'uhc2', 'uhc1', 'uhc', 'dedicado5', 'dedicado4', 'dedicado3', 'dedicado2', 'ded5', 'ded4', 'ded3', 'ded2', 'ded1', 'ded', 'gamehitodrh', 'servidor4', 'webmail', 'monitor', 'servidor001', 'servidor10', 'servidor9', 'servidor8', 'servidor7', 'servidor6', 'servidor5', 'servidor3', 'hvokfcic7sm', 'autodiscover', 'tauchet', 'hg10', 'hg9', 'hg8', 'hg7', 'hg6', 'hg5', 'hg4', 'hg3', 'hg2', 'hg1', 'scrub', 'spark', 'testpene', 'test001', 'serieyt', 'shop', 'report', 'apply', 'youtube', 'twitter', 'st', 'lost', 'sg', 'srvc1', 'srvc2', 'srvc3', 'srvc4', 'torneo', 'serv11', 'serv0', 'serv10', 'serv9', 'serv7', 'serv6', 'serv5', 'serv4', 'serv3', 'serv2', 'serv1', 'serv', 'mcp', 'paysafe', 'mu', 'radio', 'donate', 'vps03', 'vps02', 'vps01', 'xenon', 'bans', 'ns2', 'ns1', 'donar', 'new', 'appeals', 'reports', 'translations', 'marketing', 'staff', 'bugs', 'help', 'render', 'foro', 'ts3', 'git', 'analytics', 'coins', 'votos', 'docker-main', 'main', 'server3', 'cdn', 'creativo', 'yt2', 'yt', 'factions', 'solder', 'test1', 'test', 'panel', 'apolo', 'sv3', 'sv2', 'sv1', 'backups', 'zeus', 'thor', 'vps', 'build', 'web', 'dev', 'mc', 'play', 'sys', 'node1', 'node2', 'node3', 'node4', 'node5', 'node6', 'node7', 'node8', 'node9', 'node10', 'node11', 'node12', 'node13', 'node14', 'node15', 'node16', 'node17', 'node18', 'node19', 'node20', 'node001', 'node002', 'node01', 'node02', 'node003', 'sys001', 'sys002', 'go', 'admin', 'eggwars', 'bedwars', 'lobby1', 'hub', 'builder', 'developer', 'forum', 'baneos', 'ts', 'sys1', 'sys2', 'mods', 'bungee', 'bungeecord', 'array', 'spawn', 'client', 'api', 'smtp', 's1', 's2', 's3', 's4', 'server1', 'server2', 'jugar', 'login', 'mysql', 'phpmyadmin', 'demo', 'na', 'eusa', 'us', 'es', 'fr', 'it', 'ruau', 'support', 'developing', 'discord', 'backup', 'buy', 'buycraft', 'minecraft', 'prueba', 'pruebas', 'ping', 'register', 'stats', 'store', 'serie', 'buildteam', 'info', 'host', 'jogar', 'proxy', 'ovh', 'partner', 'partners', 'appeal', 'store-assets', 'builds', 'testing', 'server', 'pvp', 'skywars', 'survival', 'skyblock', 'lobby', 'hg', 'games', 'games001', 'games002', 'game001', 'game002', 'game003', 'rewards', 'rpsrv', 'ftp', 'ssh', 'jobs', 'grafana', 'vote2', 'file', 'sentry', 'enjin', 'webserver', 'xen', 'mco', 'servidor2', 'sadre', 'dev321', 'dev123', 'fl', 'rl', 'mcr', 'pe', 'tl', 'cmd', 'tla', 'pn', 'mr', 'ml', 'test2', 'test3', 'test4', 'test5', 'wlamazcsrv1', 'survival1', 'survival2', 'survival3', 'survival4', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'game1', 'game2', 'game3', 'game4', 'skypvp', 'kitpvp', 'cmd1', 'cmd2', 'cmd3', 'cmd4', 'tlauncher', 'bot', 'shop1', 'shop2', 'shop3', 'auth', 'authme', 'authserver', 'surv', 'surv1', 'surv2', 'surv3', 'surv4', 'ban', 'bungeecord1', 'bungee1', 'bungee2', 'bungee3', 'bungee4', 'bungee5', 'linux', 'ubuntu', 'clan', 'broadcast', 'minigames', 'crash', 'cheat', 'grief', 'cheating', 'hosting', 'host1', 'host2', 'host3', 'tool', 'project', 'svrgame', 'svr', 'hosthub', 'hub1', 'hub2', 'lobby2', 'lobby3', 'craft', 'crafthosting', 'overhosting', 'over', 'hosting101', 'core', 'core1', 'game', 'bro', 'fuck', 'prefix', 'protect', 'gay', 'autoconfig', 'tienda', 'pop3', 'imap', 'mail', 'cpanel', 'db', 'vpn', 'auth1', 'auth2', 'clans', 'vote3', 'vote1', 'pebg', 'cvote1', 'cvote', 'sqlstats', 'sql', 'accounts', 'dev1', 'dev2', 'dev3', 'litebans', 'local', 'private', 'privsurv', 'start', 'catcus', 'gg', 's25', 's9', 'be', 'www2', 'dashboard', 'anycast', 'app', 'embed', 'dns', 'wiki', 'i', 'x', 'images', 'my', 'java', 'swf', 'ns', 'ns3', 'secure', 'zabbix', 'dedicado1', 'dedi1', 'dedi2', 'dedi3', 'mystic', 'fun', 'eclipse', 'arena', 'us72', 'us1', 'us2', 'us3', 'us4', 'us5', 'goliathdev', 'staticassets', 'servidor1', 'pixelmon', 'mm', 'da', 'dd', 'king', 'kids', 'fly', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'hot', 'new1', 'tlf12', 'tlf13', 'tlf14', 'hype', 'hype-bungee1', 'hype-bungee2', 'hype-bungee3', 'hype-bungee4', 'nice', 'status', 'ip', 'random', 's5', 's6', 's7', 's8', 's10', 's11', 's12', 's13', 'studio', 'teamspeak', 'teamsspeak3', 'none', 'subdomain', 'build01', 'build1', 'antibot', 'botfilter', 'canada', 'tcpshield', 'files1', 'files2', 'files', 'stress', 'maquina02', 'master', 'remote', 'changelog', 'testforums', 'testserver', 'testsurvival', 'testskypvp', 'testeggwars', 'testbedwars', 'testskywars', 'testskyblock', 'pockets', 'files01', 'tmp', 'france', 'francia', 'europa', 'pex', 'rip', 'olds', 'au', 'ha', 'bw1', 'bw2', 'sw1', 'sw2', 'eg1', 'eg2', 'sky1', 'sky2', 'archive', 'database', 'iptables', 'faction', 'bots', 'tv', '2016', '2017', '2018', '2019', '2020', '2021', 'neptune', 'ha1', 'ha2', 'ha3', 'ha4', 'ha5', 'mercury', 'mars', 'venus', 'jupiter', 'urans', 'saturn', 'portal', 'bungeeportal', 'hotmail', 'boutigue', 'play-main', 'depositos', 'deposit', 'imagenes', 'bdd', 'earth', 'depositar', 'einkaufen', 'negozio', 'tent', 'ssl', 'beta', 'multicraft01', 'events', 'evidddence', 'forumlink', 'dedicado', 'dedicated', 'ipwl', 'console', 'consola', 'lib64', 'lib34', 'teste', 'photos', 'privatevps', 'vds', 'antigo', 'dox', 'members', 'users', 'acceso1', 'access2', 'acceso2', 'private01', 'private1', 'private2', 'ftp1', 'ftp2', 'ftp01', 'ftp02', 'ftp-1', 'ftp-2', 'ftp-01', 'ftp-02', 'spigot1', 'spigot2', 'spigot', 'spigot01', 'spigot02', 'paneladmin', 'admpanel', 'idiom', '25565', 'ovhpanel', 'bd', 'Tlauncher', 'shim1', 'shim2', 'shim3', 'shim4', 'shim5', 'webadmin']
        for execute in subdomains:
            try:
                iphost = str(execute) + '.' + str(context.args[0])
                check = socket.gethostbyname(str(iphost))
                if check != socket.gethostbyname(str(context.args[0])):
                    if '104.' in check:
                        cloudflare = '(CloudFlare)'
                    else:
                        cloudflare = ''

                    if 'pe.' in str(iphost):
                        pocketedition = '(Pocket Edition)'
                    else:
                        pocketedition = ''

                    final = '👍 Subdomain found:\n' + 'Subdomain: ' + str(iphost) + '\nNumeric IP: ' + str(
                        check) + ' ' + cloudflare + pocketedition
                    update.message.reply_text(final)
                else:
                    pass
            except:
                pass
        update.message.reply_text('🟢 Search completed 🟢')
    except:
        pass

def range(update: Update, context: CallbackContext) -> None:
    try:
        try:
            nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
        except nmap.PortScannerError:
            update.message.reply_text('Error with setting up scanning.')
        except:
            update.message.reply_text('Error.')

        target = context.args[0]
        ports = context.args[1]

        update.message.reply_text('Scan started')
        nm.scan(target, ports, arguments='--min-hostgroup 5 --max-hostgroup 5 --open')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = list(nm[host][proto].keys())
                lport.sort()
                try:
                    for port in lport:
                        try:
                            server = MinecraftServer(host, port)
                            status = server.status()

                            bad_chars = ['§0', '§1', '§2', '§3', '§4', '§5', '§6', '§7', '§8', '§9', '§a', '§b',
                                         '§c',
                                         '§d',
                                         '§e', '§f',
                                         '§g', '§k', '§l', '§m', '§n', '§o', '§r']

                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            s.connect((socket.gethostbyname(server.host), int(port)))
                            s.send(b'\xfe\x01')
                            data = s.recv(1024)[3:].decode("utf-16be")[3:].split("\x00")
                            s.close()
                            motd = re.sub(r'ยง[a-zA-Z0-9]', '', data[2].strip().replace('  ', '').replace('  ', ''))

                            try:
                                for i in bad_chars:
                                    motd = motd.replace(i, '')
                            except AttributeError:
                                motd = motd

                            print('Nigger: ' + socket.gethostbyname(server.host) + ':' + str(port))
                            update.message.reply_text(
                                '*⇨ IP Address:* {0}:{1}\n*⇨ Status:* 🟢\n*⇨ Players:* ({2}/{3})\n*⇨ Version:* {4} | Protocol {5}\n*⇨ MOTD:* {6}'.format(
                                    server.host,
                                    server.port,
                                    status.players.online,
                                    status.players.max,
                                    str(status.version.name).lstrip(),
                                    str(status.version.protocol).lstrip(),
                                    str(motd).lstrip()
                                ), parse_mode=ParseMode.MARKDOWN)
                        except:
                            pass
                except:
                    pass
    except:
        pass

def scan(update: Update, context: CallbackContext) -> None:
    try:
        try:
            nm = nmap.PortScanner()  # instantiate nmap.PortScanner object
        except nmap.PortScannerError:
            print('Error with setting up scanning.')
        except:
            print('Error.')

        target = context.args[0]
        selectedMode = context.args[1]
        nigga = context.args[2]

        update.message.reply_text('Scan started')
        nm.scan(target, selectedMode, arguments='-T' + nigga + ' --open')
        update.message.reply_text('Scan completed, displaying results')

        for host in nm.all_hosts():
            update.message.reply_text('Host : %s (%s)' % (nm[host].hostname(), host) + '\n' + 'Server: switched on\n=================================')
            for proto in nm[host].all_protocols():
                lport = list(nm[host][proto].keys())
                lport.sort()
                try:
                    for port in lport:
                        sleep(0.1)
                        print('Nigger: ' + socket.gethostbyname(nm[host].hostname()) + ':' + str(port))
                        try:
                            address = target
                            server = MinecraftServer(socket.gethostbyname(nm[host].hostname()), port)
                            status = server.status()

                            bad_chars = ['§0', '§1', '§2', '§3', '§4', '§5', '§6', '§7', '§8', '§9', '§a', '§b',
                                         '§c',
                                         '§d',
                                         '§e', '§f',
                                         '§g', '§k', '§l', '§m', '§n', '§o', '§r']

                            print('Nigger: ' + socket.gethostbyname(server.host) + ':' + str(port))
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            s.connect((socket.gethostbyname(server.host), int(server.port)))
                            s.send(b'\xfe\x01')
                            data = s.recv(1024)[3:].decode("utf-16be")[3:].split("\x00")
                            s.close()
                            motd = re.sub(r'ยง[a-zA-Z0-9]', '', data[2].strip().replace('  ', '').replace('  ', ''))

                            try:
                                for i in bad_chars:
                                    motd = motd.replace(i, '')
                            except AttributeError:
                                motd = motd

                            update.message.reply_text(
                                '*⇨ IP Address:* {0} ({1}:{2})\n*⇨ Status:* 🟢\n*⇨ Players:* ({3}/{4})\n*⇨ Version:* {5} | Protocol {6}\n*⇨ MOTD:* {7}'.format(
                                    address,
                                    socket.gethostbyname(server.host),
                                    server.port,
                                    status.players.online,
                                    status.players.max,
                                    str(status.version.name).lstrip(),
                                    str(status.version.protocol).lstrip(),
                                    str(motd).lstrip()
                                ), parse_mode=ParseMode.MARKDOWN)
                        except:
                            pass
                except:
                    pass
            update.message.reply_text('=================================')
    except Exception as e:
        print(e)
        pass


init('') # <-- Put token here
