

/* Arquivo do kernel que descreve definição de socket L2TP
 * linux-3.15.6/net/l2tp/l2tp_ppp.c
 * linha 36
 */
int ExemploDaEstruturaDeSocketL2TP(){

       struct sockaddr_pppol2tp sax;
       int fd;
       int session_fd;
 
       fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
 
       sax.sa_family = AF_PPPOX;
       sax.sa_protocol = PX_PROTO_OL2TP;
       sax.pppol2tp.fd = tunnel_fd;    // bound UDP socket
       sax.pppol2tp.addr.sin_addr.s_addr = addr->sin_addr.s_addr;
       sax.pppol2tp.addr.sin_port = addr->sin_port;
       sax.pppol2tp.addr.sin_family = AF_INET;
       sax.pppol2tp.s_tunnel  = tunnel_id;
       sax.pppol2tp.s_session = session_id;
       sax.pppol2tp.d_tunnel  = peer_tunnel_id;
       sax.pppol2tp.d_session = peer_session_id;
 
       session_fd = connect(fd, (struct sockaddr *)&sax, sizeof(sax));

}

/* manual page que descreve socket af_inet */
int ExemploDaEstruturaDeSocketAFINET(){
        tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0); 
        raw_socket = socket(AF_INET, SOCK_RAW, protocol);
        
       struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
        };

        /* Internet address. */
        struct in_addr {
            uint32_t       s_addr;     /* address in network byte order */
        };
}

/* Funções do kernel envolvidas no exploit
 * Mostrar os arquivos completos com essas funções na demonstração
 */

/* Função em l2tp_ppp.c com bug:
 * linux-3.15.6/net/l2tp/l2tp_ppp.c
 * linha 1357
 *
 * Função que define as opções do socket PPPoL2TP. 
 * Problema: chama udp_prot.setsockopt()
 */
/* Main setsockopt() entry point.
 * Does API checks, then calls either the tunnel or session setsockopt
 * handler, according to whether the PPPoL2TP socket is a for a regular
 * session or the special tunnel type.
 */
static int pppol2tp_setsockopt(struct socket *sock, int level, int optname,
			       char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct l2tp_session *session;
	struct l2tp_tunnel *tunnel;
	struct pppol2tp_session *ps;
	int val;
	int err;

	if (level != SOL_PPPOL2TP)
		return udp_prot.setsockopt(sk, level, optname, optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	err = -ENOTCONN;
	if (sk->sk_user_data == NULL)
		goto end;

	/* Get session context from the socket */
	err = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto end;

	/* Special case: if session_id == 0x0000, treat as operation on tunnel
	 */
	ps = l2tp_session_priv(session);
	if ((session->session_id == 0) &&
	    (session->peer_session_id == 0)) {
		err = -EBADF;
		tunnel = l2tp_sock_to_tunnel(ps->tunnel_sock);
		if (tunnel == NULL)
			goto end_put_sess;

		err = pppol2tp_tunnel_setsockopt(sk, tunnel, optname, val);
		sock_put(ps->tunnel_sock);
	} else
		err = pppol2tp_session_setsockopt(sk, session, optname, val);

	err = 0;

end_put_sess:
	sock_put(sk);
end:
	return err;
}

/* Função que vai tratar o socket P2TP
 * linux-3.15.6/net/ipv4/udp.c 
 * linha 2064
 * Função UDP que foi chamada. Como o socket não é UDP, chama ip_setsockopt
 */
int udp_setsockopt(struct sock *sk, int level, int optname,
                   char __user *optval, unsigned int optlen)
{
        if (level == SOL_UDP  ||  level == SOL_UDPLITE)
                return udp_lib_setsockopt(sk, level, optname, optval, optlen,
                                          udp_push_pending_frames);
        return ip_setsockopt(sk, level, optname, optval, optlen); // AQUI DÁ O ERRO
}

/* linux-3.15.6/net/ipv4/ip_sockglue.c
 * linha 488
 * Função que faz o ip_setsockopt. Espera um socket ip, então vai escrever o optval que não deveria...
 */
static int do_ip_setsockopt(struct sock *sk, int level,
			    int optname, char __user *optval, unsigned int optlen)
{
	struct inet_sock *inet = inet_sk(sk);
	int val = 0, err;

	switch (optname) {
	case IP_PKTINFO:
	case IP_RECVTTL:
	case IP_RECVOPTS:
	case IP_RECVTOS:
	case IP_RETOPTS:
	case IP_TOS:
	case IP_TTL:
	case IP_HDRINCL:
	case IP_MTU_DISCOVER:
	case IP_RECVERR:
	case IP_ROUTER_ALERT:
	case IP_FREEBIND:
	case IP_PASSSEC:
	case IP_TRANSPARENT:
	case IP_MINTTL:
	case IP_NODEFRAG:
	case IP_UNICAST_IF:
	case IP_MULTICAST_TTL:
	case IP_MULTICAST_ALL:
	case IP_MULTICAST_LOOP:
	case IP_RECVORIGDSTADDR:
		if (optlen >= sizeof(int)) {
			if (get_user(val, (int __user *) optval))
				return -EFAULT;
		} else if (optlen >= sizeof(char)) {
			unsigned char ucval;

			if (get_user(ucval, (unsigned char __user *) optval))
				return -EFAULT;
			val = (int) ucval;
		}
	}

	/* If optlen==0, it is equivalent to val == 0 */

	if (ip_mroute_opt(optname))
		return ip_mroute_setsockopt(sk, optname, optval, optlen);

	err = 0;
	lock_sock(sk);

	switch (optname) {
	case IP_OPTIONS:
	{
		struct ip_options_rcu *old, *opt = NULL;

		if (optlen > 40)
			goto e_inval;
		err = ip_options_get_from_user(sock_net(sk), &opt,
					       optval, optlen);
		if (err)
			break;
		old = rcu_dereference_protected(inet->inet_opt,
						sock_owned_by_user(sk));
		if (inet->is_icsk) {
			struct inet_connection_sock *icsk = inet_csk(sk);
#if IS_ENABLED(CONFIG_IPV6)
			if (sk->sk_family == PF_INET ||
			    (!((1 << sk->sk_state) &
			       (TCPF_LISTEN | TCPF_CLOSE)) &&
			     inet->inet_daddr != LOOPBACK4_IPV6)) {
#endif
				if (old)
					icsk->icsk_ext_hdr_len -= old->opt.optlen;
				if (opt)
					icsk->icsk_ext_hdr_len += opt->opt.optlen;
				icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
#if IS_ENABLED(CONFIG_IPV6)
			}
#endif
		}
		rcu_assign_pointer(inet->inet_opt, opt);
		if (old)
			kfree_rcu(old, rcu);
		break;
	}
	...
}
