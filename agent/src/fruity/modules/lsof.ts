// at this moment it does not work
// import c from "./lsof.c" with { type: "text" };

// long long ago I had one lame implementation..
// https://github.com/chaitin/passionfruit/blob/e9b736f381afbfd1470855856b52b63af5de6742/agent/Tweak.xm
//
// this is based on @miticollo's gist
// https://gist.github.com/miticollo/aa27be66fd6c12fddd9079fa4f1967bf

const c = `
#include <glib.h> /* required to use (u)int16_t, (u)int32_t, (u)int64_t */

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/arm/_types.h
  */
typedef unsigned char __uint8_t;
typedef unsigned short __uint16_t;
typedef unsigned int __uint32_t;
typedef __uint32_t __darwin_uid_t; /* [???] user IDs */
typedef __uint32_t __darwin_gid_t; /* [???] process and group IDs */
typedef long long __int64_t;
typedef __int64_t __darwin_off_t;      /* [???] Used for file sizes */
typedef __uint32_t __darwin_socklen_t; /* socklen_t (duh) */

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_uid_t.h
  */
typedef __darwin_uid_t uid_t;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_gid_t.h
  */
typedef __darwin_gid_t gid_t;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_off_t.h
  */
typedef __darwin_off_t off_t;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_u_short.h
  */
typedef unsigned short u_short;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_u_int32_t.h
  */
typedef unsigned int u_int32_t;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_fsid_t.h
  */
typedef struct fsid {
  int32_t val[2];
} fsid_t; /* file system id type */
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_u_char.h
  */
typedef unsigned char u_char;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_sa_family_t.h
  */
typedef __uint8_t sa_family_t;
/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_socklen_t.h
  */
typedef __darwin_socklen_t socklen_t;

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/syslimits.h
  */
#define PATH_MAX 1024 /* max bytes in pathname */

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/param.h
  */
/*
  * MAXPATHLEN defines the longest permissable path length after expanding
  * symbolic links. It is used to allocate a temporary buffer from the buffer
  * pool in which to do the name expansion, hence should be a power of two,
  * and must be less than or equal to MAXBSIZE.
  */
#define MAXPATHLEN PATH_MAX

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/_types/_in_addr_t.h
  */
typedef __uint32_t in_addr_t; /* base type for internet address */

#if (G_BYTE_ORDER == G_LITTLE_ENDIAN)
  #define ntohs(x) ((((x) & 0x00FF) << 8) | (((x) & 0xFF00) >> 8))
#else
  #define ntohs(x) (x)
#endif

/*
  * Internet address (a structure for historical reasons)
  */
struct in_addr {
  in_addr_t s_addr;
};

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet6/in6.h
  */
#define INET6_ADDRSTRLEN 46
/*
  * IPv6 address
  */
typedef struct in6_addr {
  union {
    __uint8_t __u6_addr8[16];
    __uint16_t __u6_addr16[8];
    __uint32_t __u6_addr32[4];
  } __u6_addr; /* 128-bit IP6 address */
} in6_addr_t;

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/proc_info.h
  */
/*
  * A copy of stat64 with static sized fields.
  */
struct vinfo_stat {
  uint32_t vst_dev;          /* [XSI] ID of device containing file */
  uint16_t vst_mode;         /* [XSI] Mode of file (see below) */
  uint16_t vst_nlink;        /* [XSI] Number of hard links */
  uint64_t vst_ino;          /* [XSI] File serial number */
  uid_t vst_uid;             /* [XSI] User ID of the file */
  gid_t vst_gid;             /* [XSI] Group ID of the file */
  int64_t vst_atime;         /* [XSI] Time of last access */
  int64_t vst_atimensec;     /* nsec of last access */
  int64_t vst_mtime;         /* [XSI] Last data modification time */
  int64_t vst_mtimensec;     /* last data modification nsec */
  int64_t vst_ctime;         /* [XSI] Time of last status change */
  int64_t vst_ctimensec;     /* nsec of last status change */
  int64_t vst_birthtime;     /*  File creation time(birth)  */
  int64_t vst_birthtimensec; /* nsec of File creation time */
  off_t vst_size;            /* [XSI] file size, in bytes */
  int64_t vst_blocks;        /* [XSI] blocks allocated for file */
  int32_t vst_blksize;       /* [XSI] optimal blocksize for I/O */
  uint32_t vst_flags;        /* user defined flags for file */
  uint32_t vst_gen;          /* file generation number */
  uint32_t vst_rdev;         /* [XSI] Device ID */
  int64_t vst_qspare[2];     /* RESERVED: DO NOT USE! */
};

struct vnode_info {
  struct vinfo_stat vi_stat;
  int vi_type;
  int vi_pad;
  fsid_t vi_fsid;
};

struct proc_fdinfo {
  int32_t proc_fd;
  uint32_t proc_fdtype;
};

struct vnode_info_path {
  struct vnode_info vip_vi;
  char vip_path[MAXPATHLEN]; /* tail end of it  */
};

struct proc_fileinfo {
  uint32_t fi_openflags;
  uint32_t fi_status;
  off_t fi_offset;
  int32_t fi_type;
  uint32_t fi_guardflags;
};

struct vnode_fdinfo {
  struct proc_fileinfo pfi;
  struct vnode_info pvi;
};

struct vnode_fdinfowithpath {
  struct proc_fileinfo pfi;
  struct vnode_info_path pvip;
};

struct in4in6_addr {
  u_int32_t i46a_pad32[3];
  struct in_addr i46a_addr4;
};

struct in_sockinfo {
  int insi_fport;       /* foreign port */
  int insi_lport;       /* local port */
  uint64_t insi_gencnt; /* generation count of this instance */
  uint32_t insi_flags;  /* generic IP/datagram flags */
  uint32_t insi_flow;

  uint8_t insi_vflag;  /* ini_IPV4 or ini_IPV6 */
  uint8_t insi_ip_ttl; /* time to live proto */
  uint32_t rfu_1;      /* reserved */
  /* protocol dependent part */
  union {
    struct in4in6_addr ina_46;
    struct in6_addr ina_6;
  } insi_faddr; /* foreign host table entry */
  union {
    struct in4in6_addr ina_46;
    struct in6_addr ina_6;
  } insi_laddr; /* local host table entry */
  struct {
    u_char in4_tos; /* type of service */
  } insi_v4;
  struct {
    uint8_t in6_hlim;
    int in6_cksum;
    u_short in6_ifindex;
    short in6_hops;
  } insi_v6;
};

/*
  * TCP Sockets
  */

#define TSI_T_NTIMERS 4

struct tcp_sockinfo {
  struct in_sockinfo tcpsi_ini;
  int tcpsi_state;
  int tcpsi_timer[TSI_T_NTIMERS];
  int tcpsi_mss;
  uint32_t tcpsi_flags;
  uint32_t rfu_1;    /* reserved */
  uint64_t tcpsi_tp; /* opaque handle of TCP protocol control block */
};

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h
  */
/*
  * [XSI] Definitions for UNIX IPC domain.
  */
struct sockaddr_un {
  unsigned char sun_len;  /* sockaddr len including null */
  sa_family_t sun_family; /* [XSI] AF_UNIX */
  char sun_path[104];     /* [XSI] path name (gag) */
};

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/socket.h
  */
#define AF_UNIX 1           /* local to host (pipes) */
#define AF_INET 2           /* internetwork: UDP, TCP, etc. */
#define AF_INET6 30         /* IPv6 */
#define SOCK_MAXADDRLEN 255 /* longest possible addresses */

/*
  * Unix Domain Sockets
  */

struct un_sockinfo {
  uint64_t unsi_conn_so; /* opaque handle of connected socket */
  uint64_t
      unsi_conn_pcb; /* opaque handle of connected protocol control block */
  union {
    struct sockaddr_un ua_sun;
    char ua_dummy[SOCK_MAXADDRLEN];
  } unsi_addr; /* bound address */
  union {
    struct sockaddr_un ua_sun;
    char ua_dummy[SOCK_MAXADDRLEN];
  } unsi_caddr; /* address of socket connected to */
};

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/net/if.h
  */
#define IF_NAMESIZE 16

/*
  * PF_NDRV Sockets
  */
struct ndrv_info {
  uint32_t ndrvsi_if_family;
  uint32_t ndrvsi_if_unit;
  char ndrvsi_if_name[IF_NAMESIZE];
};

/*
  * Kernel Event Sockets
  */
struct kern_event_info {
  uint32_t kesi_vendor_code_filter;
  uint32_t kesi_class_filter;
  uint32_t kesi_subclass_filter;
};

/* defined in
  * https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/kern_control.h
  */
/*!
  *       @defined MAX_KCTL_NAME
  *   @discussion Kernel control names must be no longer than
  *       MAX_KCTL_NAME.
  */
#define MAX_KCTL_NAME 96

/*
  * Kernel Control Sockets
  */
struct kern_ctl_info {
  uint32_t kcsi_id;
  uint32_t kcsi_reg_unit;
  uint32_t kcsi_flags;       /* support flags */
  uint32_t kcsi_recvbufsize; /* request more than the default buffer size */
  uint32_t kcsi_sendbufsize; /* request more than the default buffer size */
  uint32_t kcsi_unit;
  char kcsi_name[MAX_KCTL_NAME]; /* unique nke identifier, provided by DTS */
};

/*
  * VSock Sockets
  */
struct vsock_sockinfo {
  uint32_t local_cid;
  uint32_t local_port;
  uint32_t remote_cid;
  uint32_t remote_port;
};

struct sockbuf_info {
  uint32_t sbi_cc;
  uint32_t sbi_hiwat; /* SO_RCVBUF, SO_SNDBUF */
  uint32_t sbi_mbcnt;
  uint32_t sbi_mbmax;
  uint32_t sbi_lowat;
  short sbi_flags;
  short sbi_timeo;
};

enum {
  SOCKINFO_IN = 1,
  SOCKINFO_TCP = 2,
};

struct socket_info {
  struct vinfo_stat soi_stat;
  uint64_t soi_so;  /* opaque handle of socket */
  uint64_t soi_pcb; /* opaque handle of protocol control block */
  int soi_type;
  int soi_protocol;
  int soi_family;
  short soi_options;
  short soi_linger;
  short soi_state;
  short soi_qlen;
  short soi_incqlen;
  short soi_qlimit;
  short soi_timeo;
  u_short soi_error;
  uint32_t soi_oobmark;
  struct sockbuf_info soi_rcv;
  struct sockbuf_info soi_snd;
  int soi_kind;
  uint32_t rfu_1; /* reserved */
  union {
    struct in_sockinfo pri_in;             /* SOCKINFO_IN */
    struct tcp_sockinfo pri_tcp;           /* SOCKINFO_TCP */
    struct un_sockinfo pri_un;             /* SOCKINFO_UN */
    struct ndrv_info pri_ndrv;             /* SOCKINFO_NDRV */
    struct kern_event_info pri_kern_event; /* SOCKINFO_KERN_EVENT */
    struct kern_ctl_info pri_kern_ctl;     /* SOCKINFO_KERN_CTL */
    struct vsock_sockinfo pri_vsock;       /* SOCKINFO_VSOCK */
  } soi_proto;
};

struct socket_fdinfo {
  struct proc_fileinfo pfi;
  struct socket_info psi;
};

/* defns of process file desc type */
#define PROX_FDTYPE_VNODE 1
#define PROX_FDTYPE_SOCKET 2
#define PROX_FDTYPE_KQUEUE 5
#define PROX_FDTYPE_NETPOLICY 9

/* Flavors for proc_pidinfo() */
#define PROC_PIDLISTFDS 1
#define PROC_PIDLISTFD_SIZE (sizeof(struct proc_fdinfo))

/* Flavors for proc_pidfdinfo */

#define PROC_PIDFDVNODEPATHINFO 2
#define PROC_PIDFDVNODEPATHINFO_SIZE (sizeof(struct vnode_fdinfowithpath))

#define PROC_PIDFDSOCKETINFO 3
#define PROC_PIDFDSOCKETINFO_SIZE (sizeof(struct socket_fdinfo))

/* https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getservbyport.3.html#//apple_ref/doc/man/3/getservbyport
  */
struct servent {
  char *s_name;     /* official name of service */
  char **s_aliases; /* alias list */
  int s_port;       /* port service resides at */
  char *s_proto;    /* protocol to use */
};

/* https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/libsyscall/wrappers/libproc/libproc.h
  */
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer,
                        int buffersize);
extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer,
                          int buffersize);

/* other functions */
extern int getpid();
extern void *malloc(size_t);
extern int snprintf(char *, size_t, const char *, ...);
extern const char *inet_ntop(int, const void *, char *,
                              socklen_t); /* in libkern*/
extern struct servent *getservbyport(int, const char *);

/* my functions */
extern void push_vnode(int32_t, char *);
extern void push_socket(int32_t, char *, char *, int, char *, char *, int,
                        char *);
extern void error(char *);

void fds(void) {
  // Figure out the size of the buffer needed to hold the list of open FDs
  int bufferSize = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
  if (bufferSize == 0)
    error("Unable to get open file handles");

  // Get the list of open FDs
  struct proc_fdinfo *procFDInfo = (struct proc_fdinfo *)malloc(bufferSize);
  if (!procFDInfo)
    error("Out of memory. Unable to allocate buffer with %d bytes");
  /* https://github.com/palominolabs/get_process_handles/issues/1#issue-314083604
    */
  /* http://disq.us/p/dvodv4 */
  int returnedSize =
      proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, procFDInfo, bufferSize);
  int numberOfProcFDs = returnedSize / PROC_PIDLISTFD_SIZE;

  for (int i = 0; i < numberOfProcFDs; i++) {
    struct proc_fdinfo *finfo = &procFDInfo[i];
    switch (finfo->proc_fdtype) {
    case PROX_FDTYPE_VNODE: {
      // A file is open
      struct vnode_fdinfowithpath vnodeInfo;
      int bytesUsed =
          proc_pidfdinfo(getpid(), finfo->proc_fd, PROC_PIDFDVNODEPATHINFO,
                          &vnodeInfo, PROC_PIDFDVNODEPATHINFO_SIZE);
      if (bytesUsed == PROC_PIDFDVNODEPATHINFO_SIZE)
        push_vnode(finfo->proc_fd, vnodeInfo.pvip.vip_path);
      break;
    }
    case PROX_FDTYPE_SOCKET: {
      // A socket is open
      struct socket_fdinfo socketInfo;
      int bytesUsed =
          proc_pidfdinfo(getpid(), finfo->proc_fd, PROC_PIDFDSOCKETINFO,
                          &socketInfo, PROC_PIDFDSOCKETINFO_SIZE);
      if (bytesUsed == PROC_PIDFDSOCKETINFO_SIZE) {
        switch (socketInfo.psi.soi_kind) {
        case SOCKINFO_TCP:  // Type: TCP
        case SOCKINFO_IN: { // Type: UDP
          int family, lport, rport;
          char lip[INET6_ADDRSTRLEN], rip[INET6_ADDRSTRLEN];
          struct in_sockinfo *s;

          family = socketInfo.psi.soi_family;

          s = socketInfo.psi.soi_kind == SOCKINFO_TCP
                  ? &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini
                  : &socketInfo.psi.soi_proto.pri_in;
          if ((family == AF_INET) || (family == AF_INET6)) {
            if (family == AF_INET) {
              inet_ntop(AF_INET, &s->insi_laddr.ina_46.i46a_addr4, lip,
                        sizeof(lip));
              inet_ntop(AF_INET, &s->insi_faddr.ina_46.i46a_addr4, rip,
                        sizeof(rip));
            } else {
              inet_ntop(AF_INET6, &s->insi_laddr.ina_6, lip, sizeof(lip));
              inet_ntop(AF_INET6, &s->insi_faddr.ina_6, rip, sizeof(rip));
            }

            struct servent any = {"*"}; // \u2731
            struct servent *lsp = 0, *fsp = 0;
            lport = ntohs(s->insi_lport);
            rport = ntohs(s->insi_fport);
            lsp = lport ? getservbyport(lport, 0) : &any;
            fsp = rport ? getservbyport(rport, 0) : &any;

            char *protocol;
            if (family == AF_INET6) {
              protocol =
                  (socketInfo.psi.soi_kind == SOCKINFO_TCP) ? "TCP6" : "UDP6";
            } else {
              protocol =
                  (socketInfo.psi.soi_kind == SOCKINFO_TCP) ? "TCP" : "UDP";
            }

            char *lsp_name =
                (lsp) ? lsp->s_name : "Unknown (local) service name";
            char *fsp_name =
                (fsp) ? fsp->s_name : "Unknown (remote) service name";
            push_socket(finfo->proc_fd, protocol, lip, lport, lsp_name, rip,
                        rport, fsp_name);
          } else if (family == AF_UNIX) {
          }
        }
        }
      }
      break;
    }
    case PROX_FDTYPE_KQUEUE: {
      // TODO: missing body
      break;
    }
    case PROX_FDTYPE_NETPOLICY: {
      // TODO: missing body
      break;
    }
    default: {
      char str[100];
      snprintf(str, sizeof(str), "Unknown process file desc type: %d!",
                finfo->proc_fdtype);
      error(str);
      break;
    }
    }
  }
}

`;

export const enum ProcFDType {
  VNODE = "vnode",
  SOCKET = "socket",
  KQUEUE = "kqueue",
}

export interface VnodeFD {
  fd: number;
  path: string;
  type: ProcFDType.VNODE;
}

export interface SocketFD {
  fd: number;
  protocol: string;
  lip: string;
  lport: number;
  lsp: string;
  rip: string;
  rport: number;
  fsp: string;
  type: ProcFDType.SOCKET;
}

type FileDescriptor = VnodeFD | SocketFD;

const libsystem = Module.load("/usr/lib/libSystem.B.dylib");

export function fds() {
  const fds: FileDescriptor[] = [];

  const push_vnode = new NativeCallback(
    (fd: number, path: NativePointer) => {
      fds.push({
        fd,
        path: path.readUtf8String()!,
        type: ProcFDType.VNODE,
      });
    },
    "void",
    ["int32", "pointer"], // TODO: more details?
  );

  const push_socket = new NativeCallback(
    function (
      fd: number,
      protocol: NativePointer,
      lip: NativePointer,
      lport: number,
      lsp: NativePointer,
      rip: NativePointer,
      rport: number,
      fsp: NativePointer,
    ): void {
      fds.push({
        fd: fd,
        protocol: protocol.readUtf8String()!,
        lip: lip.readUtf8String()!,
        lport,
        lsp: lsp.readUtf8String()!,
        rip: rip.readUtf8String()!,
        // Remote port will be 0 when the FD represents a listening socket
        rport,
        fsp: fsp.readUtf8String()!,
        type: ProcFDType.SOCKET,
      });
    },
    "void",
    [
      "int32",
      "pointer",
      "pointer",
      "int",
      "pointer",
      "pointer",
      "int",
      "pointer",
    ],
  );

  const error = new NativeCallback(
    function (msg: NativePointer): void {
      throw new Error(msg.readUtf8String()!);
    },
    "void",
    ["pointer"],
  );

  const cm: CModule = new CModule(c, {
    proc_pidinfo: libsystem.getExportByName("proc_pidinfo"),
    proc_pidfdinfo: libsystem.getExportByName("proc_pidfdinfo"),
    getpid: libsystem.getExportByName("getpid"),
    malloc: libsystem.getExportByName("malloc"),
    snprintf: libsystem.getExportByName("snprintf"),
    inet_ntop: libsystem.getExportByName("inet_ntop"),
    getservbyport: libsystem.getExportByName("getservbyport"),
    push_vnode,
    push_socket,
    error,
  });

  new NativeFunction(cm.fds, "void", [])();
  return fds;
}
