
#!/bin/bash
clear
clear
versao=3.9
clear
op() {
echo -e "\033[97m[\033[92m$1\033[97m]\033[91m $2 $3 $4 $5 $6 $7\033[97m"
}
b="\033[97m"
v="\033[92m"
Ver="\033[91m"
am="\033[93m"
 if [[ -d /etc/squid ]]; then
    if [[ -f /etc/squid/squid.conf ]];then
     mv /etc/squid/squid.conf /etc/squid/squid.conf.old
     echo -e "squid instalado!"
     sleep 0.5
     echo -e "Parando squid..."
     service squid stop 2>/dev/null
    fi
if [[ -f /usr/bin/screen ]]; then
true
else
echo -e "Instalando screen..."
    if apt-get install screen -y 1>/dev/null 2>/dev/null; then
         true
    else
         yum install screen -y 1>/dev/null 2>/dev/null
     fi
 fi
 fi
 if [[ -d /etc/squid3 ]]; then
     if [[ -f /etc/squid3/squid.conf ]];then
     mv /etc/squid3/squid.conf /etc/squid3/squid.conf.old
     echo -e "squid3 instalado!"
     sleep 0.5
     echo -e "Parando squid3..."
     service squid stop 2>/dev/null
    fi
 fi
 
if [[ -d /etc/proxy-socks ]]; then
    if [[ -d /etc/proxy-socks/info-users ]]; then
        true
    else
        mkdir /etc/proxy-socks/info-users
    fi
 if [[ -f /etc/proxy-socks/proxy.py ]]; then
  true
 else
 echo -e "\033[01;32m ✔ Instalando proxy-socks..."
 apt-get update 1>/dev/null 2>/dev/null
  wget -qO- /dev/null https://raw.githubusercontent.com/fenixtm/PROXY-INJECTOR/master/proxy.py > /etc/proxy-socks/proxy.py
  sleep 1
IP=$(wget -4qO- "http://whatismyip.akamai.com/")
echo -e "\033[01;32m"
read -p "Confirme seu IP: " -e -i $IP IP
echo -e "\033[0m"
if [[ -z "$IP" ]];then
echo -e "IP invalido"
sleep 1
echo -e "\033[01;32m"
read -p "Digite seu IP: " IP
echo -e "\033[0m"
fi
IPPRO=$(cat /etc/proxy-socks/proxy.py|grep "server =" | awk {'print $3'})
sed -i "s/server = $IPPRO/server = '$IP'/" /etc/proxy-socks/proxy.py
sleep 1
echo -e "\033[01;32m"
echo -e "Iniciando proxy-socks..."
screen -dmS screen python3 /etc/proxy-socks/proxy.py 80
screen -dmS screen python3 /etc/proxy-socks/proxy.py 8080
screen -dmS screen python3 /etc/proxy-socks/proxy.py 8799 
screen -dmS screen python3 /etc/proxy-socks/proxy.py 3128 
echo -e "Proxy-socks ativo nas portas: /033[01;31m  8080,80,3128,8799"
echo -e "\033[0m"
 fi
else
echo -e "Instalando proxy-socks..."
apt-get update 1>/dev/null 2>/dev/null
mkdir /etc/proxy-socks
wget -qO- /dev/null https://raw.githubusercontent.com/fenixtm/PROXY-INJECTOR/master/proxy.py> /etc/proxy-socks/proxy.py
IP=$(wget -4qO- "http://whatismyip.akamai.com/")
read -p "Confirme seu IP: " -e -i $IP IP
if [[ -z "$IP" ]];then
echo -e "IP invalido"
sleep 1
read -p "Digite seu IP: " IP
fi
sleep 1
IPPRO=$(cat /etc/proxy-socks/proxy.py|grep "server =" | awk {'print $3'})
sed -i "s/server = $IPPRO/server = '$IP'/" /etc/proxy-socks/proxy.py
echo -e "Iniciando proxy-socks..."
screen -dmS screen python3 /etc/proxy-socks/proxy.py 80
screen -dmS screen python3 /etc/proxy-socks/proxy.py 8080
screen -dmS screen python3 /etc/proxy-socks/proxy.py 8799 
screen -dmS screen python3 /etc/proxy-socks/proxy.py 3128 
echo -e "Proxy-socks ativo nas portas: 8080,80,3128,8799"
fi
statusproxy2 () {
if ps x | grep proxy.py|grep -v grep 1>/dev/null 2>/dev/null; then
statusproxy="$v"ON""
else
statusproxy="$Ver"OFF""
fi
}
veri_443 () {
if cat /etc/ssh/sshd_config|grep "Port 443" 1>/dev/null; then
  true
  else
  echo -e "Adicionando porta 443 no sshd_config..."
  sed -i 's/Port 22/Port 22\nPort 443/' /etc/ssh/sshd_config
  service ssh restart 1>/dev/null 2>/dev/null
  service sshd restart 1>/dev/null 2>/dev/null
fi
}
banner () {
echo -e "\033[01;36m

 _   __   _       _   _____   _____   _____  
| | |  \ | |     | | | ____| /  ___| |_   _| 
| | |   \| |     | | | |__   | |       | |   
| | | |\   |  _  | | |  __|  | |       | |   
| | | | \  | | |_| | | |___  | |___    | |   
|_| |_|  \_| \_____/ |_____| \_____|   |_|   
        \033[01;31m CRIADO: @FENIX_LINUX \033[0m

"
}
banner
   if [[ -d /etc/proxy-socks/info-users ]]; then
        true
    else
        mkdir /etc/proxy-socks/info-users
    fi
main () {
veri_443
statusproxy2
echo -e ""
echo -e "\033[01;35m ESCOLHA UMA OPÇAO [01-08] \033[0m"

echo -e "\033[04;01;31m======================[$v"Menu"\033[04;31m]========================\033[0m"
op 01 "\033[01;37;42m ALTERAR MENSAGEM DE ERRO                     " "\033[0m" $(echo -e "$b($v"403 Erro"$b)")           
op 02 "\033[01;37;42m ALTERAR MENSAGEM DE SUCESSO                  " "\033[0m" $(echo -e "$b($v"200 Ok"$b)")         
op 03 "\033[01;37;42m PARAR/INICIAR PROXY-SOCKS                    " "\033[0m" $(echo -e "$b($v$statusproxy$b)")       
op 04 "\033[01;37;42m VER USUARIOS CRIADO                          "                                      "\033[0m"
op 05 "\033[01;37;42m CRIAR USUARIOS                               "                                      "\033[0m"
op 06 "\033[01;37;42m DELETAR USUARIOS                             "                                      "\033[0m"
op 07 "\033[01;37;42m MONITOR SSH                                  "                                      "\033[0m"
op 08 "\033[01;37;42m SAIR                                         "                                      "\033[0m"                                                                                              
echo -e "\033[04;01;31m======================[$v"Menu"\033[04;31m]========================\033[0m"
echo -e "\033[01;37;36m"
read -p "Escolha uma opcao : " option
echo -e "\033[0m"
 while [ "$option" != 01 -o "$option" != 1 -o "$option" != 02 -o "$option" != 2 -o "$option" != 03 -o "$option" != 3 -o "$option" != 04 -o "$option" != 4 -o "$option" != 05 -o "$option" != 5 -o "$option" != 06 -o "$option" != 6 -o "$option" != 07 -o "$option" != 7 -o "$option" != 08 -o "$option" != 8 ]
 do
   if [[ $option = 01 ||$option = 1 ||$option = 02 ||$option = 2 ||$option = 03 ||$option = 3 ||$option = 04 ||$option = 4 ||$option = 05 ||$option = 5 ||$option = 06 ||$option = 6 ||$option = 07 ||$option = 7 ||$option = 08 ||$option = 8 ]]; then

if [[ "$option" = "01" || "$option" = "1" ]]; then
echo -e "$b===============[$v"MENSAGEM$Ver ERRO"$b]==============="
   read -p "Mensagem: " msg1
   echo -e "Parando proxy-socks..."
   pidproxy=$(ps x|grep "proxy.py"|awk -F "pts" {'print $1'})
   kill -9 $pidproxy 2>/dev/null
   echo -e "Alterando mensagem..."
   msg2=$(cat /etc/proxy-socks/proxy.py | grep "msg2 =" | awk -F = '{print $2}')
   sed -i  "s/msg2 =$msg2/msg2 = '$msg1'/" /etc/proxy-socks/proxy.py
   echo -e "Iniciando proxy-socks..."
   screen -dmS screen python3 /etc/proxy-socks/proxy.py 80
   screen -dmS screen python3 /etc/proxy-socks/proxy.py 8080
   screen -dmS screen python3 /etc/proxy-socks/proxy.py 8799 
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 3128 
	echo -e "\033[01;37;36m"
  echo -e "Proxy-socks ativo nas portas: 8080,80,3128,8799"
  echo -e "Pronto, proxy-socks esta com a mensagem de erro $msg1"
  read -p 'Enter continuar...'  enter
	echo -e "\033[0m"
  main
fi
if [[ "$option" = "2" || "$option" = "2" ]]; then

echo -e "$b=============[$v"MENSAGEM SUCESSO"$b]=============="
   read -p "Mensagem: " msg1
   echo -e "Parando proxy-socks..."
   pidproxy=$(ps x|grep "proxy.py"|awk -F "pts" {'print $1'})
   kill -9 $pidproxy 2>/dev/null
   echo -e "Alterando mensagem..."
   msg2=$(cat /etc/proxy-socks/proxy.py | grep "msg1 =" | awk -F = '{print $2}')
   sed -i  "s/msg1 =$msg2/msg1 = '$msg1'/" /etc/proxy-socks/proxy.py
   echo -e "Iniciando proxy-socks..."
   screen -dmS screen python3 /etc/proxy-socks/proxy.py 80
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 8080
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 8799 
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 3128 
  echo -e "Proxy-socks ativo nas portas: 8080,80,3128,8799"
  echo -e "Pronto, proxy-socks estÃ¡ com a mensagem de sucesso $msg1"
  read -p 'Enter continuar...'  enter
  clear
  main
fi
if [[ "$option" = "03" || "$option" = "3" ]]; then
  if ps x | grep "proxy.py"|grep -v grep 1>/dev/null 2>/dev/null; then
echo -e "$b================[$v"PARAR SOCKS"$b]================="
   echo -e "Parando proxy-socks..."
   pidproxy=$(ps x|grep "proxy.py"|awk -F "pts" {'print $1'})
   kill -9 $pidproxy 1>/dev/null 2>/dev/null
   echo -e "Proxy-socks parado"
   read -p 'Enter continuar...'  enter
   clear
   main
 else
  echo -e "$b==============[$v"INICIAR SOCKS"$b]================="
   echo -e "Iniciando proxy-socks..."
   screen -dmS screen python3 /etc/proxy-socks/proxy.py 80
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 8080
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 8799 
  screen -dmS screen python3 /etc/proxy-socks/proxy.py 3128 
   echo -e "Proxy-socks ativo nas portas: 8080,80,3128,8799"
   sleep 1
   echo -e "Proxy-socks iniciado"
   read -p 'Enter continuar...'  enter
   clear
   main
  fi
fi
if [[ "$option" = "04" || "$option" = "4" ]]; then
echo -e "==============================================="
echo -e  "\033[96mUsuario       Senha       Data     Conexoes$b"
echo -e "==============================================="
for user in `awk -F : '$3 >= 1000 {print $1}' /etc/passwd|grep -v nobody`
do
if [[ -f /etc/proxy-socks/info-users/$user ]]; then
senha=$(cat /etc/proxy-socks/info-users/$user|awk  -F : {'print $2'})
data=$(cat /etc/proxy-socks/info-users/$user|awk -F : {'print $3'})
echo -ne "$am"
printf '%-14s%-9s%-15s%s\n' "$user" "$senha" "$data" "$(ps -u $user |grep sshd |wc -l)"
echo -ne "$b"
else
echo -ne "$am"
data=null
senha=null
printf '%-14s%-12s%-12s%s\n' "$user" "$senha" "$data" "$(ps -u $user |grep sshd |wc -l)"
echo -ne "$b"
fi
echo -e "$b-----------------------------------------------"
done
read -p "Enter continuar..." enter
clear
main
fi
 if [[ "$option" = 05 || "$option" = 5 ]]; then
     nome () {
     read -p "Nome: " nome
         if awk -F : '$3 >= 1000 {print $1}' /etc/passwd | grep $nome 1>/dev/null 2>/dev/null; then
	         echo -e "\033[91mUsuario \033[92m$nome\033[91m ja existe\033[97m"
	         nome
         fi
         }
         nome
     read -p "Senha: " senha
     read -p "Data: " data
     validade=$(date '+%C%y/%m/%d' -d " +$data days")
     validadebr=$(date '+%d/%m/%C%y' -d " +$data days")
     echo -e "Criando usuario $nome..."
     useradd -M -N -s /bin/false $nome -e $validade
     (echo "$senha";echo "$senha")|passwd $nome 1>/dev/null 2>/dev/null
     sleep 1
     clear
     echo -e "$v"Sucesso!"$b"
     echo ""
     echo -e "\033[93mUsuario: $v$nome"
     echo -e "\033[93mSenha: $v$senha"
     echo -e "\033[93mData: $v$validadebr$b"
     echo "$nome:$senha:$validadebr" > /etc/proxy-socks/info-users/$nome
     read -p "Enter continuar..." enter 
     clear
     main
 fi
 if [[ "$option" = 06 || "$option" = 6 ]]; then
echo -e "$b=================[$v"Usuarios"$b]=================="
user_del () {
awk -F : '$3 >= 1000 { print $1 }' /etc/passwd | grep -v "nobody"| grep -v "glemysson" > /tmp/users.txt
i=0
rm /tmp/users 1>/dev/null 2>/dev/null
op 00 - MENU
echo ''
while read usuario
do
i=$(($i+1))
if [[ $i = [1-9] ]]; then
c="0$i"
else
c=$i
fi
op $c - $usuario
echo "$i: $usuario" >> /tmp/users
done < /tmp/users.txt
if [[ -f /tmp/users ]]; then
mum=$(cat /tmp/users | wc -l)
if [[ "$num" = '0' ]]; then
echo -e "\033[1;31mVoce nao tem usuarios existente\033[1;37m"
read -p "Enter continuar..." enter
main
else
true
fi
else
echo -e "\033[1;31mVoce nao tem usuarios existente\033[1;37m"
read -p "Enter continuar..." enter
main
fi
echo -e "$b---------------------------------------"
echo -n -e "\033[1;37mDeletar: ";read del
while [ "$del" != [0-$(cat /tmp/users.txt|wc -l)] ]; do
if [[ "$del" = [0-$(cat /tmp/users.txt|wc -l)] ]]; then
if [[ "$del" = '0' || "$del" = '00' ]]; then
main
fi
user=$(cat /tmp/users|grep $del:|awk -F : {'print $2'})
us=$(echo $user)
echo -e "Deletando usuario \033[1;32m$us\033[1;37m" 
 sleep 0.5
pids=$(ps -u $us 1>/dev/null 2>/dev/null |awk {'print $1'})
 kill "$pids" >/dev/null 2>/dev/null
 rm /etc/proxy-socks/info-users/$us 1>/dev/null 2>/dev/null
 userdel -f $us 1>/dev/null 2>/dev/null
echo -e "Usuario \033[1;32m$us\033[1;37m Deletado"
read -p "Enter continuar..."
clear
user_del
else
echo -n -e "\033[1;37mDeletar: ";read del
fi
done
}
user_del
 fi
 if [[ "$option" = 07 || "$option" = 7 ]]; then
 echo -e "==============================================="
 users=$(awk -F : '$3 > 900 { print $1 }' /etc/passwd |grep -v "nobody" |grep -vi polkitd |grep -vi systemd-[a-z] |grep -vi systemd-[0-9] |sort)
echo -e  "\033[96mUsuario       Status      Conexoes      Tempo$b"
 echo -e "==============================================="
for user in $users; do
echo -e "$b-----------------------------------------------"
	if [[ $(ps -u $user |grep sshd |wc -l) -eq 0 ]]; then
		status=$(echo -e "$Ver""offline        $am")
		echo -ne "$am"
		printf '%-14s%-14s%-11s%s\n' "$user" "$status" "$(ps -u $user |grep sshd |wc -l)" "00:00" 
	else
		status=$(echo -e "$v""Online         $am")
		echo -ne "$am"
		printf '%-14s%-13s%-11s%s\n' "$user" "$status" "$(ps -u $user |grep sshd |wc -l)" "$(ps -o etime $(ps -u $user |grep sshd |awk 'NR==1 {print $1}')|awk 'NR==2 {print $1}')"
	fi
echo -e "$b-----------------------------------------------"
done

read -p "Enter continuar..." enter
clear
 main
 fi
 
if [[ "$option" = "08" || "$option" = "8"   ]]; then
echo -e "$b===================[$v"SAIR"$b]===================="
   echo -e "Saindo..."
   sleep 1
   exit
fi
else
read -p "Escolha uma opcao: " option
fi
done
}
main
