//Author: root4root@gmail.com

int tun_alloc(char *dev, int flags) 
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ( (fd = open(clonedev, O_RDWR)) < 0 ) {
        my_err("Unable to open clonable device %s", clonedev);
        return fd;
    }
 
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    } 

    if ( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        close(fd);
        return err;
    }

    return fd;
}

int cread(int fd, char *buf, int n)
{
    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
        my_err("Error, while reading data. Abort.");
        exit(1);
    }
  
    return nread;
}

void *tun_x(void *x_void_ptr)
{
    int tap_fd;
    int nread;
    char buffer[BUFSIZE];
    
 
    if ( (tap_fd = tun_alloc(globcfg.dev_name, globcfg.dev_mode | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tun/tap interface %s. Abort.", globcfg.dev_name);
        exit(1);
    }
    
    while(1) {
        nread = cread(tap_fd, buffer, BUFSIZE);
        
        if (globcfg.pcap_filter != NULL) {
            usleep(15000); //Wait for libpcap time out.
            if ( (curts - ts) < 2 ) {
                do_debug("Read %d bytes from the tap interface\n", nread);
                break;
            } 
        } else {
             break;   
        }
    }
  
    ts = time(NULL);
    
    status = 1;
    
    close(tap_fd);
  
    my_info("Executing START command...");
    
    if (system(globcfg.cmd_path_start) != 0) {
        my_err("Warning! Executable command doesn't return 0 (%s)", globcfg.cmd_path_start);
    }
  
    return 0;
}
