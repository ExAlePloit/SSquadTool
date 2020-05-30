import os
import colored
import sys
import socket
import re
import time
import platform
import base64
import json
import requests
from cryptography.fernet import Fernet
from dns import reversename, resolver
from colored import fg, bg, attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def clear():
    if platform.system() == "Linux":
        os.system("clear")
    elif platform.system() == "Darwin":
        os.system("clear")
    elif platform.system() == "Windows":
        os.system("cls")

def main():
    clear()
    banner()
    menu()

def getData(url):
    response = requests.get(url)
    return response.json()

def menu():
    sezione = ["", "Nmap Scan", "Qubo Scan", "SubDomain Finder", "Server Info", "Online Player Listener", "PlayerInfo" ,"Exit"]
    while True:
        clear()
        banner()
        for i in range(1,len(sezione)): 
            print(stampamenu(i, str(sezione[i])))
        menuScelto = scelta("\n Choice: ")
        if menuScelto == str(len(sezione)-1):
            sys.exit(1)
        elif menuScelto == "1":
            Nmap_Scan()
        elif menuScelto == "2":
            Qubo_Scan()
        elif menuScelto == "3":
            SubDomain_Finder()
        elif menuScelto == "4":
            Server_Info()
        elif menuScelto == "5":
            Online_Player_Listener()
        elif menuScelto == "6":
            Player_Info()
            
def Nmap_Scan():
    def Simple_Scan():
        nmapcommand = "nmap -p 25560-25580 -T5 -sV -v --open "
        ip = scelta("\n Ip or DNS: ")
        print()
        os.system(nmapcommand + ip)
    def Advanced_Scan():
        nmapcommand = "nmap -p 1-9,12-17,100-120,200-220,300-320,400-420,500-520,600-620,700-720,800-820,900-920,1000-1020,2000-2020,3000-3020,4000-4020,5000-5020,6000-6020,7000-7020,8000-8020,8100-8120,9000-9020,10000-10100,11000-11100,12000-12100,13000-13100,14000-14100,15000-15100,16000-16100,17000-17100,18000-18100,19000-19100,20000-20300,21000-21100,22000-22100,23000-23100,24000-24100,25000-30000,31000-31100,32000-32100,33000-33100,34000-34100,35000-35100,36000-36100,37000-37100,38000-38100,39000-39100,40000-40500,41000-41100,42000-42100,43000-43100,44000-44100,45000-45100,46000-46100,47000-47100,48000-48100,49000-49300,50000-50400,51000-51100,52000-52100,53000-53100,54000-54100,55000-55100,56000-56100,57000-57100,58000-58100,59000-59100,60000-60300,61000-61100,62000-62100,63000-63100,64000-64100,65000-65535 -T5 -sV -v --open "
        ip = scelta("\n Ip or DNS: ")
        print()
        os.system(nmapcommand + ip)
    def Custom_Scan():
        comando = scelta("\n Nmap Command: ")
        os.system(comando)
    ripeti = True
    while ripeti:
        ripeti = False
        print()
        sezione = ["", "Simple Scan", "Advanced Scan", "Custom Scan", "Back"]
        for i in range(1,len(sezione)): 
            print(stampamenu(i, str(sezione[i])))
        menuScelto = scelta("\n Choice: ")
        if menuScelto == "4":
            return
        elif menuScelto == "1":
            Simple_Scan()
        elif menuScelto == "2":
            Advanced_Scan()
        elif menuScelto == "3":
            Custom_Scan()
        else:
            ripeti = True
    pause()
    
    
def Qubo_Scan():
    qubocommand= "java -Dfile.encoding=UTF-8 -jar qubo.jar -ports 1-9,12-17,100-120,200-220,300-320,400-420,500-520,600-620,700-720,800-820,900-920,1000-1020,2000-2020,3000-3020,4000-4020,5000-5020,6000-6020,7000-7020,8000-8020,8100-8120,9000-9020,10000-10100,11000-11100,12000-12100,13000-13100,14000-14100,15000-15100,16000-16100,17000-17100,18000-18100,19000-19100,20000-20300,21000-21100,22000-22100,23000-23100,24000-24100,25000-30000,31000-31100,32000-32100,33000-33100,34000-34100,35000-35100,36000-36100,37000-37100,38000-38100,39000-39100,40000-40500,41000-41100,42000-42100,43000-43100,44000-44100,45000-45100,46000-46100,47000-47100,48000-48100,49000-49300,50000-50400,51000-51100,52000-52100,53000-53100,54000-54100,55000-55100,56000-56100,57000-57100,58000-58100,59000-59100,60000-60300,61000-61100,62000-62100,63000-63100,64000-64100,65000-65535  -th 2700 -ti 480 -c 3 -noping -range "
    def QuboScan00xx():
        ip = scelta("\n Ip: ")
        ipSplittato = ip.split(".")
        print()
        os.system(qubocommand + ipSplittato[0] + "." + ipSplittato[1] + ".0.0-" + ipSplittato[0] + "." + ipSplittato[1] + ".255.255")
    def QuboScan000x():
        ip = scelta("\n Ip: ")
        ipSplittato = ip.split(".")
        print()
        os.system(qubocommand + ipSplittato[0] + "." + ipSplittato[1] + "." + ipSplittato[2] + ".0-" + ipSplittato[0] + "." + ipSplittato[1] + "." + ipSplittato[2] + ".255")
    def Custom_Scan():
        comando = scelta("\n Range (10.20.30.0-10.20.30.0-255): ")
        os.system(qubocommand + comando)

    ripeti = True
    while ripeti:
        ripeti = False
        print()
        sezione = ["", "Scan XXX.XXX.0-255.0-255", "Scan XXX.XXX.XX.0-255", "Custom Range", "Back"]
        for i in range(1,len(sezione)): 
            print(stampamenu(i, str(sezione[i])))
        menuScelto = scelta("\n Choice: ")
        if menuScelto == "4":
            return
        elif menuScelto == "1":
            QuboScan00xx()
        elif menuScelto == "2":
            QuboScan000x()
        elif menuScelto == "3":
            Custom_Scan()
        else:
            ripeti = True
    pause()
def SubDomain_Finder():
    subDomains = ["www", "www2", "dashboard", "anycast", "admin", "app", "panel", "embed", "autoconfig", "autodiscover", "private", "mail", "direct", "direct-connect", "cpanel", "ftp", "pop", "imap", "forum", "blog", "portal", "beta", "dev", "webmail", "record", "ssl", "dns", "ts3", "m", "mobile", "help", "wiki", "client", "server", "api", "i", "x", "cdn", "images", "my", "java", "swf", "smtp", "ns", "ns1", "ns2", "ns3", "mx", "server1", "server2", "test", "vpn", "secure", "login", "store", "shop", "zabbix", "cacti", "mysql", "search", "monitor", "nagios", "munin", "data", "old", "stat", "stats", "preview", "phpmyadmin", "db", "demo", "status", "gateway", "gateway1", "gateway2", "node", "mc", "play", "jogar", "serie", "tienda", "build", "buildteam", "new", "news", "ftb", "na", "us", "eu", "pr", "ts", "staff", "register", "ftb", "serie", "download", "descarga", "downloads", "descargas", "vm", "multicraft", "forums", "ssh", "administrator", "email", "access", "home", "game", "gaming", "idiom", "developer", "support", "photos", "app", "foro", "discord", "backup", "config", "demo", "web", "ban", "bans", "en", "ca", "ads", "ad", "archive", "es", "cloud", "developers", "development", "go", "host", "premium", "ded1", "ded", "dedi1", "dedi", "server01", "servidor", "dedicado", "dedicated", "nodo", "donate", "donaciones", "minecraft", "mc01", "mc02", "ayuda", "nl", "documentation", "ip", "sql", "priv", "redirect", "hg", "pixelmon", "ips", "server3", "dash", "www1", "menu", "hub", "inicio", "node01", "buy", "vote", "votar", "contact", "contacto", "guide", "guia", "baneos", "user", "info", "proxy", "proxy01", "proxy1", "mx1", "pay", "bb", "in", "as", "payment", "fun", "redirection", "lobby", "sv", "sv01", "sv1", "1", "2", "3", "01", "02", "03", "s1", "s2", "s", "d", "d1", "team", "ca1", "fr", "fr1", "pvp", "auth", "usk", "usk1", "domain", "img", "join", "stores", "tiendas", "mc1", "mc2", "mc3", "mc4", "mc5", "mc6", "mc7", "mc8", "mc9", "mc10", "mc11", "mc12", "mc8", "dox", "ozr", "ozr1", "manager", "manage", "vps", "vps1", "vps01", "t", "f", "fairness", "verify", "pass0", "service", "services", "service01", "service1", "services01", "services1", "srv", "srv1", "srv01", "ve", "br", "sys", "donatii", "survival", "mega", "ggtx", "uhc", "toxic", "open", "sf", "sf1", "sf01", "pixel", "ru", "node-2", "node-1", "node-01", "node-02", "sys1", "api1", "yt", "yt1", "apixelados", "youtube", "youtube1", "youtube01", "servidor1", "servidor2", "servidor01", "servidor02", "game1", "u", "prox.1", "prox", "prox1", "prox01", "uhc1", "ded.1", "de", "bungee", "bungeecord", "bungeecord1", "bungeecord01", "bungee1", "bungee01", "ovh", "ovh1", "ovh01", "ca-01", "ca-1", "builds", "mysql-1", "mysql-01", "srv-01", "srv-1", "srv-02", "srv-03", "mclogin", "zeusproxy", "ecplise", "craftbukkit", "spigot", "ovh2", "ovh3", "antiddos", "vs", "primary", "secondary", "one", "two", "testing", "tester", "mcauth", "proxypipe", "sql1", "sql01", "network", "la", "ar", "arg", "cl", "partner", "partners", "example", "prueba", "shoping", "privatevps", "members", "users", "vpn1", "vpn01", "dev1", "dev01", "build1", "build01", "subdomain", "canada", "france", "francia", "europa", "europe", "database", "database1", "database01", "ms", "ping", "suscribe", "su", "enter", "loja", "privado", "anuncio", "anuncios", "announce", "announces", "appeals", "appeal", "reports", "report", "bteam", "whitelist", "plugin", "script", "cloudfare", "pueblo", "pp", "cf", "skype", "contactanos", "contactar", "0", "mojang", "apelar", "code", "coder", "ww0", "ww1", "ww2", "port", "porta", "puerto", "ports", "puertos", "vnc", "putty", "ssh1", "ssh01", "root", "craft", "launcher", "voting", "voteserver", "servervote", "votos", "play1", "play01", "tekkit", "fml", "forge", "configurando", "configuracion", "configuration", "files", "us1", "na1", "eu1", "na01", "eu01", "us01", "mcna", "mcna1", "mcna01", "mceu", "mceu1", "mceu01", "ovhgame", "ovhgame1", "ovhgame01", "ovhgaming", "ovhgaming1", "ovhgaming01", "gameovh", "gamingovh", "gameovh01", "gameovh1", "gamingovh1", "gamingovh01", "govh", "ovhg", "root1", "root01", "tos", "terms", "comprar", "bot", "antibot", "antibots", "bots", "sw1", "sw01", "sw", "faction", "factions", "skywars", "serv1", "serv2", "serv01", "serv02", "serv", "buycraft", "mod", "mods", "hosting", "multicraft1", "multicraft01", "events", "event", "ipv4", "ipv6", "irc", "cdn1", "d1", "d2", "d01", "d02", "n1", "n2", "n01", "n02", "webdisk", "jouer", "facebook", "twitter", "serveur", "prive", "serveur1", "serveur2", "serveur01", "serveur02", "reset", "resetpassword", "password", "passwordreset", "js", "html", "php", "bungee-1", "bungee-2", "bungee-01", "bungee-02", "proxy-1", "proxy-2", "proxy-01", "proxy-02", "alpha", "vps-1", "vps-2", "vps-01", "vps-02", "mysql1", "mysql01", "mysql2", "mysql02", "ftp1", "ftp2", "ftp01", "ftp02", "ftp-1", "ftp-2", "ftp-01", "ftp-02", "ssh-1", "ssh-01", "ssh-2", "ssh-01", "error", "base", "pl", "25565", "bd", "buildt", "python", "paypal", "donar", "apache", "windows", "window", "linux", "e-mail", "uk", "it", "telegram", "ovh-1", "ovh-2", "ovh-01", "ovh-02", "sa", "teste", "loja1", "xd", "teamspeak", "teamspeak3", "none", "sr", "git", "svn", "remote", "sip", "firewall", "iptable", "iptables", "correo", "intranet", "da", "track", "ftpd", "ftpadmin", "localhost", "mg", "msg", "radio", "pop3", "directory", "imagenes", "repo", "vip", "sg", "be", "ep", "test2", "drive", "gb", "sites", "jobs", "marketing", "mail2", "lyncdiscover", "ci", "jira", "painel", "mssql", "maquina", "maquinats", "lists", "ts2", "agenda", "web01", "web1", "gitlab", "github", "straight", "msoid", "calendar", "mobilemail", "jp", "ticket", "tickets", "voice", "ok", "entrar", "logueo", "loguearse", "system", "sistema", "control", "remoto", "net", "usuario", "usuarios", "miembros", "miembro", "bukkit", "spigot01", "spigot1", "spigot2", "spigot02", "hi", "hello", "world", "gob", "google", "media", "sign", "signin", "aiuto", "built", "sesion", "session", "connection", "connecting", "reconnect", "reconectar", "redirectip", "red", "redip", "redireccionar", "archivos", "video", "videos", "codificacion", "edit", "editar", "lol", "cpanel1", "cpanel01", "cpanel2", "cpanel02", "alts", "alt", "stress", "stresser", "bw", "bedwars", "bw1", "bw01", "bw2", "bw02", "sk", "skript", "luckperms", "lp", "rank", "webhost", "hostweb", "web-host", "community", "sync", "we", "bdd", "basededatos", "acceso1", "acceso2", "access1", "access2", "sadre", "eventteam", "et", "clan", "clans", "placeholder", "placeholderapi", "vote2", "vote3", "vote4", "vote1", "pe", "mco", "pebg", "cvote1", "cvote", "cvote2", "cvote3", "xen", "xenforo", "reader", "confluence", "storeassets", "violations", "c", "pc", "r53", "chidev", "staticassets", "ma", "me", "pedev", "rpsrv", "gamehitodrh", "xenon", "mcp", "mu", "paysafe", "social", "baneados", "rp", "samp", "shoprp", "wow", "holo", "imprint", "chatlog", "rp1", "rp01", "acp", "shop-admin", "l1", "l2", "l11", "dl", "msp", "impressum", "impresora", "front", "beta-karambyte", "store-assets", "merch", "wwww", "playa", "front2", "front1", "release", "pss", "mvn", "mariaum", "bugs", "bug", "pirata", "insanehg", "antigo", "maquina1", "maquina2", "maquina3", "maquina01", "maquina02", "master", "antiguo", "postularte", "logs", "clanseu", "clansus", "nfo", "nfoservers", "nfoserver", "apidoc", "2017", "2018", "2016", "2015", "2014", "feedback", "bp", "evidence", "forumlink", "storeredirect", "avatar", "uno", "dos", "tres", "cuatro", "node1", "node2", "node3", "node4", "node5", "node6", "node7", "node8", "node9", "node10", "node11", "node12", "node13", "node14", "node15", "node16", "node17", "node18", "node19", "node20", "node21", "node22", "sys2", "sys3", "sys4", "sys5", "s3", "ded2", "ded3", "ded4", "ded5", "ded6", "ded7", "ded8", "ded9", "ded10", "ded11", "ded12", "ded13", "ded14", "ded15", "ded16", "ded17", "ded18", "ded19", "ded20", "ded21", "ded22", "vps2", "vps3", "vps4", "vps5", "serieyt", "ytserie", "location", "mexico", "cuenta", "account", "sqlstats", "sqlstats1", "sqlstats2", "accounts", "accounts2", "accounts1", "server4", "sv2", "api1", "api01", "api2", "api02", "owlmessenger", "hg1", "hg2", "hg3", "hg4", "hg5", "sc", "za", "heroes", "il", "se", "studio", "kids", "kid", "consent", "rules", "tv", "gdata", "pex", "rip", "olds", "feedproxy", "docs", "apis", "contributor", "gmail", "hotmail", "boutique", "play-main", "depositos", "deposit", "depositar", "buycraft", "einkaufen", "negozio", "tent", "compra", "compras", "extras", "bart", "lisa", "eva", "xxx", "execute", "console", "consola", "v1", "ip1", "ip2", "ip01", "ip02", "beta1", "beta2", "de1", "de2", "de01", "de02", "dedic1", "dedic2", "dedic01", "dedic02", "cfr", "v2", "v01", "v02", "rat", "njrat", "fast", "gbps", "10gbps", "1gbps", "100mbps", "tienda1", "tienda2", "tienda01", "tienda02", "ipts", "iptv", "premium1", "premium2", "premium01", "premium02", "adminpanel", "paneladmin", "admpanel", "paneladm", "adm", "private1", "private2", "private01", "private02", "ovhvps", "ovhded", "ovhdedi", "panelovh", "ovhpanel", "unodo", "unodos", "unodo1", "unodo2", "unodos1", "unodos2", "nodos1", "nodos2", "nodos01", "nodos02", "run", "bin", "sbin", "boot", "lib", "mnt", "opt", "lib64", "tmp", "proc", "var", "pockets", "testforums", "changelog", "files1", "files2", "files01", "files02", "au", "ha", "ha1", "ha2", "ha3", "ha4", "ha5", "mercury", "neptune", "mars", "venus", "jupiter", "uranus", "saturn", "earth"]
    
    DNS = scelta("\nDNS (Not www.google.com Only google.com): ")
    i = 0
    link = []
    ip = []
    print (fg(33) +"\n Looking for DNS...\n")
    for subdomain in subDomains:
            try:
                    test1= str(subdomain)+"."+str(DNS)
                    test2= str(socket.gethostbyname(str(test1)))
                    link.insert(i,test1)
                    ip.insert(i,test2)
                    i += 1
            except:
                    pass
    print (fg(33) + "\n Results:")
    x = 0
    ipUnici = []
    for i in range(0,len(ip)):
        if ipUnici.count(ip[i]) == 0:
            ipUnici.insert(x, ip[i])
            print (fg(33) + "\n Ip: " + fg(15) + ip[i])
            x += 1
            for y in range(0,len(ip)):
                if ip[y] == ipUnici[x-1]:
                    print (fg(33) + " >> " + fg(15) + str(link[y]))

    pause()
def Server_Info():

    def color1():
        return fg(33)
    def color2():
        return fg(15)
    
    def return_key(text, keys, response):
        value = response
        for key in keys:
            if key in value:
                value = value[key]
            else:
                return "0"
        return color1() + text + color2() + str(value)

    def stampa_array_key(text, keys, response):
        value = response
        for key in keys:
            if key in value:
                value = value[key]
            else:
                return 
        print(color1() + text + color2())
        for item in value:
            print(color1() + " >> " + color2() + item)
        
    def stampa_key(string):
        if string != "0":
            print(string)
            
    target = scelta("\n Ip or DNS: ")
    server = getData("https://api.mcsrvstat.us/2/" + target)
    if server["online"]:
        stampa_key(fg(10) + "\n Server Online")        
        stampa_key(return_key("\n Hostname: ", ["hostname"], server))
        stampa_key(return_key("\n Ip: ", ["ip"], server) + return_key("\t\tPort: ", ["port"], server))
        stampa_key(return_key("\n Version: ", ["version"], server) + return_key("\t\tProtocol: ", ["protocol"], server))
        stampa_key(return_key("\n Map: ", ["map"], server))
        stampa_array_key("\n Motd: ", ["motd","clean"], server)
        stampa_key(return_key("\n PlayerOnline: ", ["players","online"], server) + return_key("/", ["players","max"], server) + return_key("\t\tSoftware: ", ["software"], server))
        stampa_array_key("\n PlayerList: ", ["players","list"], server)
        stampa_array_key("\n Plugins: ", ["plugins","raw"], server)
        stampa_array_key("\n Mods: ", ["mods","raw"], server)
        stampa_array_key("\n Info: ", ["info","clean"], server)
        
    else:
        print(fg(1) + "\n Server Offline")
        stampa_key(return_key("\n Hostname: ", ["hostname"], server))
    pause()
    
def Online_Player_Listener():
    def playerList(target):
        server = getData("https://api.mcsrvstat.us/2/" + target)
        try:
            value = server["players"]["list"]
            return value
        except:
            if server["online"]:
                return 1
            else:
                return 0

    def creaFile(name, target):
        try:
            os.mkdir('SSquadOutputs')
        except FileExistsError:
            pass
        with open(os.getcwd() + "/SSquadOutputs/" + name + ".txt",'w') as file:
            file.write("Target: " + target)

    def scriviFile(name):
        try:
            print(fg(15) + "\n\n Press [ctrl + C] to stop...\n" )
            while True:
                with open(os.getcwd() + "/SSquadOutputs/" + name + ".txt",'r+') as file:
                    lines = [i.strip() for i in file]
                    firstline = lines[0]
                    if firstline.count("Target: ") != 0:
                        target = firstline.replace("Target: ", "")
                        players = playerList(target)
                        if players == 0:
                            print(fg(1) +"\n The server is offline")
                            return
                        elif players == 1:
                            print(fg(1) +"\n It is not possible to take the player list of this server")
                            return
                        else:
                            for player in players:
                                if lines.count(player) == 0:
                                    file.write("\n" + player)
                            print(fg(33) + " Total Player: " + fg(15) + str(len(lines) - 1))
                    else:
                        print(fg(1) +" File not found")
                        return
                time.sleep(20)
                
        except KeyboardInterrupt:
            return
        except FileNotFoundError:
            print(fg(1) +" File not found")
        
                
    def New_Listening():
        target = scelta("\n Ip or DNS: ")
        players = playerList(target)
        if players == 0:
            print(fg(1) +"\n The server is offline")
            return
        elif players == 1:
            print(fg(1) +"\n It is not possible to take the player list of this server")
            return
        else:
            name = scelta("\n Enter the name of the file: ")
            creaFile(name, target)
            scriviFile(name)
            
    def Continue_Listening():
        name = scelta("\n Enter the name of the file: ")
        scriviFile(name)
    
    
    ripeti = True
    while ripeti:
        ripeti = False
        print()
        sezione = ["", "New Listening", "Continue Listening ", "Back"]
        for i in range(1,len(sezione)): 
            print(stampamenu(i, str(sezione[i])))
        menuScelto = scelta("\n Choice: ")
        if menuScelto == "3":
            return
        elif menuScelto == "1":
            New_Listening()
        elif menuScelto == "2":
            Continue_Listening()
        else:
            ripeti = True
    pause()
def Player_Info():
    player = scelta("\n Nick: ")
    try:
        json_premium = getData("https://api.mojang.com/users/profiles/minecraft/" + player)
        print (fg(33) +"\n Type: " +fg(15) + "Premium")
        print (fg(33) +"\n Online UUID: " +fg(15) + json_premium["id"])
        json_historyNick = getData("https://api.mojang.com/user/profiles/" + json_premium["id"] + "/names")
        print (fg(33) +"\n History names:")
        for name in json_historyNick:
            print(fg(33) +" >> " + fg(15) +name.get("name"))
    except:
        print (fg(33) +"Type: " +fg(15) + "Cracked")
    pause()


def stampamenu(num, stringa):
    return fg(33) + " (" + fg(15) + str(num) + fg(33) + ") " + stringa

def scelta(stringa):
    return input(fg(1) + stringa + fg(15))

def pause():
    pause = input (fg(1) + "\n\n Press [Enter] - to continue...")

def banner():
	print (fg(27) + '''                                                 
\t\t  ██████   ██████   █████   █    ██  ▄▄▄      ▓█████▄ 
\t\t▒██    ▒ ▒██    ▒ ▒██▓  ██▒ ██  ▓██▒▒████▄    ▒██▀ ██▌
\t\t░ ▓██▄   ░ ▓██▄   ▒██▒  ██░▓██  ▒██░▒██  ▀█▄  ░██   █▌
\t\t  ▒   ██▒  ▒   ██▒░██  █▀ ░▓▓█  ░██░░██▄▄▄▄██ ░▓█▄   ▌
\t\t▒██████▒▒▒██████▒▒░▒███▒█▄ ▒▒█████▓  ▓█   ▓██▒░▒████▓ 
\t\t▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░ ▒▒▓  ▒ 
\t\t░ ░▒  ░ ░░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░   ▒   ▒▒ ░ ░ ▒  ▒ 
\t\t░  ░  ░  ░  ░  ░     ░   ░  ░░░ ░ ░   ░   ▒    ░ ░  ░ 
\t\t      ░        ░      ░       ░           ░  ░   ░    
\t\t                                               ░       
		''')
	print (fg(15) + "\t\t\t\t\t\tVer. 0.8")
	print (fg(15)  + "\t\t\t\t\t\tBy ExAlePloit @Aless1010")


main()
