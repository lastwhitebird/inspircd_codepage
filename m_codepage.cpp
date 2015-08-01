/*       | Inspire Internet Relay Chat Daemon |
 *       +------------------------------------+
 *
 *  InspIRCd: (C) 2002-2008 InspIRCd Development Team
 * See: http://www.inspircd.org/wiki/index.php/Credits
 *
 * This program is free but copyrighted software; see
 *            the file COPYING for details.
 *
 * ---------------------------------------------------
 */

/*
   by Chernov-Phoenix Alexey (Phoenix@RusNet) mailto:phoenix /email address separator/ pravmail.ru */

/* $ModDesc: Translates raw irc traffic from/to client choosing conversion encoding by server port or user choice. */
/* $ModAuthor: Alexey */
/* $ModAuthorMail: Phoenix@RusNet */
/* $ModDepends: core 2.0 */


#include "inspircd.h"
#include <iconv.h>
#include "modules.h"

/* a record containing incoming and outgoing convertion descriptors and encoding name */
struct io_iconv
{
    iconv_t in, out;
    std::string encoding;
    char * intable;
    char * outtable;
};

/* a read buffer for incomplete multibyte characters. As they are just characters and they are incomplete, it's 3 bytes long :) */
struct io_buffer
{
    char buffer[3];
    char count;
};

typedef nspace::hash_map<int, int> hash_common;			/* port/file descriptor 	-> encoding index */
typedef nspace::hash_map<std::string, int> hash_str;		/* encoding name 		-> encoding index */
typedef nspace::hash_map<int, Module *> hash_io;		/* file descriptor		-> old io handler */
typedef nspace::hash_map<int, std::string> hash_save;		/* file descriptor		-> encoding name */
typedef nspace::hash_map<int, io_buffer> hash_buffer;		/* file descriptor		-> read multibyte buffer */

const char * modulenames[] = {"m_ssl_gnutls.so", "m_ssl_openssl.so", "m_xmlsocket.so"};
static Implementation eventlist[] = { I_OnRehash, I_OnHookIO, I_OnUnloadModule, I_On005Numeric, I_OnWhoisLine, I_OnUserRegister };

#define with_iterator(type, name) \
	static type name; \
	typedef type name ## _type

//static hash_common fd_hash, port_hash;
with_iterator(hash_common, fd_hash);
with_iterator(hash_common, port_hash);
with_iterator(hash_str, name_hash);
with_iterator(hash_io, io_hash);
with_iterator(hash_save, save_hash);
with_iterator(hash_save, buffer_hash_write);
with_iterator(hash_buffer, buffer_hash);
static std::vector<io_iconv> recode;
static unsigned int bound;

char toUpper_ (char c)
{
    return std::toupper(c);
}
void ToUpper(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(), toUpper_);
}

#define if_found_in_hash(a, b, c) \
	c ## _type::iterator a; \
	a = c.find(b); \
	if (a != c.end())

#define if_not_local_user(variable, user) \
	LocalUser* variable = IS_LOCAL( user ); if (! variable )

#define ModifyIOHook(eh, mod)  (&eh)->DelIOHook(); \
		(&eh)->AddIOHook( mod )

class ModuleCodepageBase : public Module
{
    public:
        StringExtItem ecodepage;
        ModuleCodepageBase()
            : ecodepage("codepage", this)
        {};

        void set_codepage(LocalUser* u, int c)
        {
            fd_hash[u->eh.GetFd()] = c;
            ecodepage.set(u, recode[c].encoding);
            ServerInstance->PI->SendMetaData(u, "codepage", recode[c].encoding);
        }
};

class CommandCodepage : public SplitCommand
{
    public:
        CommandCodepage(Module* mod) : SplitCommand(mod, "CODEPAGE", 0, 1)
        {
            syntax = "<codepage> | SHOW | NEXT";
        }

        CmdResult HandleLocal(const std::vector<std::string>& parameters, LocalUser *user)
        {
            std::string codepage = "SHOW";
            if (parameters.size() > 0)
            {
                codepage = parameters[0];
                ToUpper(codepage);
            }

            if (codepage == "SHOW") /* A horrible expression! to find the name of users's current codepage! However that works. (pokerface) */
            {
                codepage = recode[fd_hash[user->eh.GetFd()]].encoding;
                user->WriteNumeric(700, "%s %s :is your current translation scheme", user->nick.c_str(), codepage.c_str());
                return CMD_SUCCESS;
            }

            if (codepage == "NEXT")
            {
                int index = fd_hash[user->eh.GetFd()] + 1;
                if ((unsigned int)index >= bound)
                    index = 0;
                codepage = recode[index].encoding;
            }

            if_found_in_hash(iter, codepage, name_hash)
            {
                if (fd_hash[user->eh.GetFd()] != iter->second)
                {
                    ((ModuleCodepageBase*)(Module*)creator)->set_codepage(user, iter->second);
                    user->WriteNumeric(700, "%s %s :is now your translation scheme", user->nick.c_str(), codepage.c_str());
                    return CMD_SUCCESS;
                }
                else
                {
                    user->WriteNumeric(752, "%s %s :is already your current translation scheme", user->nick.c_str(), codepage.c_str());
                }
            }
            else
            {
                user->WriteNumeric(750, "%s :Wrong or unsupported codepage: %s", user->nick.c_str(), codepage.c_str());
            }

            return CMD_FAILURE;
        }
};

/* took it from SAQUIT :) */
class CommandSacodepage : public Command
{
    public:
        CommandSacodepage(Module* mod) : Command(mod, "SACODEPAGE", 2, 2)
        {
            flags_needed = 'o';
            syntax = "<nick> { <codepage> | NEXT }";
            TRANSLATE3(TR_NICK, TR_TEXT, TR_END);
        }

        CmdResult Handle(const std::vector<std::string>& parameters, User *user)
        {
            User* dest = ServerInstance->FindNick(parameters[0]);
            if (dest)
            {
                if (ServerInstance->ULine(dest->server))
                {
                    user->WriteNumeric(990, "%s :Cannot use an SA command on a u-lined client", user->nick.c_str());
                    return CMD_FAILURE;
                }

                std::string codepage = parameters[1];
                ToUpper(codepage);

                ServerInstance->SNO->WriteGlobalSno('A', std::string(user->nick) + " used SACODEPAGE to force " + std::string(dest->nick) + " have a codepage of " + codepage);

                /* Pass the command on, so the client's server can handle it properly.*/
                if_not_local_user(udest, dest)
                return CMD_SUCCESS;

                /* SACODEPAGE will be a bit different */
                if (codepage == "SHOW")
                {
                    codepage = recode[fd_hash[udest->eh.GetFd()]].encoding;
                    dest->WriteNumeric(700, "%s %s :is now your translation scheme", dest->nick.c_str(), codepage.c_str());
                    return CMD_SUCCESS;
                }

                if (codepage == "NEXT")
                {
                    int index = fd_hash[udest->eh.GetFd()] + 1;
                    if ((unsigned int)index >= bound)
                        index = 0;
                    codepage = recode[index].encoding;
                }

                if_found_in_hash(iter, codepage, name_hash)
                {
                    if (fd_hash[udest->eh.GetFd()] != iter->second)
                    {
                        ((ModuleCodepageBase*)(Module*)creator)->set_codepage(udest, iter->second);
                        dest->WriteNumeric(700, "%s %s :is now your translation scheme", dest->nick.c_str(), codepage.c_str());
                        return CMD_SUCCESS;
                    }
                    else
                    {
                        user->WriteNumeric(752, "%s %s :is already your current translation scheme", user->nick.c_str(), codepage.c_str());
                    }
                }
                else
                {
                    user->WriteNumeric(750, "%s :Wrong or unsupported codepage: %s", user->nick.c_str(), codepage.c_str());
                }

                /* -- end of CODEPAGE cut */
            }
            else
            {
                user->WriteServ("NOTICE %s :*** Invalid nickname '%s'", user->nick.c_str(), parameters[0].c_str());
            }

            return CMD_FAILURE;
        }

        RouteDescriptor GetRouting(User* user, const std::vector<std::string>& parameters)
        {
            User* dest = ServerInstance->FindNick(parameters[0]);
            if (dest)
                return ROUTE_OPT_UCAST(dest->server);
            return ROUTE_LOCALONLY;
        }
};

class CommandCodepages : public Command
{
    public:
        CommandCodepages(Module* mod) : Command(mod, "CODEPAGES", 0, 1)
        {
            syntax = "[<servername>]";
        }

        RouteDescriptor GetRouting(User* user, const std::vector<std::string>& parameters)
        {
            if (parameters.size() > 0)
                return ROUTE_UNICAST(parameters[0]);
            return ROUTE_LOCALONLY;
        }

        CmdResult Handle(const std::vector<std::string>& parameters, User *user)
        {
            std::string servname;
            if (parameters.size() < 1)
            {
                servname = std::string(ServerInstance->Config->ServerName);
            }
            else
            {
                servname = parameters[0];
            }

            if (servname != ServerInstance->Config->ServerName)
            {
                // Give extra penalty if a non-oper queries the /CODEPAGES of a remote server
                LocalUser* localuser = IS_LOCAL(user);
                if ((localuser) && (!IS_OPER(user)))
                    localuser->CommandFloodPenalty += 2000;
                return CMD_SUCCESS;
            }

            for (unsigned int i = 0; i < bound; ++i)
                user->WriteNumeric(701, "%s : Codepage available: %s", user->nick.c_str(), recode[i].encoding.c_str());

            user->WriteNumeric(702, "%s :*** End of CODEPAGES", user->nick.c_str());
            return CMD_SUCCESS;
        }
};

class ModuleCodepage : public ModuleCodepageBase
{
    private:
        ServiceProvider iohook;
        CommandCodepage mycommand;
        CommandSacodepage mycommand2;
        CommandCodepages mycommand3;
        std::string icodepage, dcodepage;
    public:
        ModuleCodepage()
            : iohook(this, "codepage/lwb", SERVICE_IOHOOK), mycommand(this), mycommand2(this), mycommand3(this)
        {
        }

        ModResult OnUserRegister(LocalUser *user)
        {
            if_found_in_hash(iter, user->eh.GetFd(), fd_hash)
            {
                ecodepage.set(user, recode[iter->second].encoding);
                ServerInstance->PI->SendMetaData(user, "codepage", recode[iter->second].encoding);
            }
            return MOD_RES_PASSTHRU;
        }

        ModResult OnWhoisLine(User* user, User* dest, int &numeric, std::string &text)
        {
            /* We use this and not OnWhois because this triggers for remote, too */
            if (numeric == 312)
            {
                /* Insert our numeric before 312 */
                const std::string* ucodepage = ecodepage.get(dest);
                if (ucodepage)
                {
                    ServerInstance->SendWhoisLine(user, dest, 320, "%s %s :codepage is %s", user->nick.c_str(), dest->nick.c_str(), ucodepage->c_str());
                }
            }
            /* Don't block anything */
            return MOD_RES_PASSTHRU;
        }

        void init()
        {
            OnRehash(NULL);
            ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist) / sizeof(Implementation));
            ServerInstance->Modules->AddService(iohook);
            ServerInstance->Modules->AddService(mycommand);
            ServerInstance->Modules->AddService(mycommand2);
            ServerInstance->Modules->AddService(mycommand3);
            ServerInstance->Modules->AddService(ecodepage);
        }

        void SaveExisting()
        {
            save_hash.clear();
            LocalUserList::const_iterator iter;
            for (iter = ServerInstance->Users->local_users.begin(); iter != ServerInstance->Users->local_users.end(); ++iter)
            {
                int fd = (*iter)->eh.GetFd();
                if_found_in_hash(iter2, fd, fd_hash)
                {
                    std::string codepage = recode[iter2->second].encoding;
                    save_hash[fd] = codepage;
                }
            }
        }

        void HookExisting()
        {
            LocalUserList::const_iterator iter;
            for (iter = ServerInstance->Users->local_users.begin(); iter != ServerInstance->Users->local_users.end(); ++iter)
            {
                /* Hook the user with our module for stacking... (and save his/her/its (that may be also a bot ;) ) ->IOHook ) */
                int fd = (*iter)->eh.GetFd();
                Module * hk = (*iter)->eh.GetIOHook();
                if (hk && (hk != this))
                {
                    if_found_in_hash(iter3, fd, io_hash)
                    io_hash[fd] = hk;
                }
                ModifyIOHook((*iter)->eh, this);
                /* restoring saved or the default encoding on a port for a user, OnStreamSocketAccept code */
                int found = 0;
                if_found_in_hash(iter4, fd, save_hash)
                {
                    if_found_in_hash(iter5, iter4->second, name_hash)
                    found = iter5->second;
                    else
                    {
                        addavailable(iter4->second, false);
                        if_found_in_hash(iter6, iter4->second, name_hash)
                        found = iter6->second;
                    }
                }
                if (found == 0)
                {
                    if_found_in_hash(iter2, (*iter)->GetServerPort(), port_hash)
                    found = iter2->second;
                }
                set_codepage((*iter), found);
            }
        }

        void itableconvert(char* table, char* dest, const char* source, int n)
        {
            --n;
            for (; n >= 0; --n)
            {
                dest[n] = table[(unsigned char)source[n]];
            }
        }

        void makeitable(iconv_t cd, char * &table)
        {
            int i;
            char tmp[2];
            tmp[1] = 0; /* trailing 0 */

            table = new char[256];
            for (i = 0; i < 0x100; ++i)
            {
                tmp[0] = (char)i;
                char * src = tmp;
                char * dest = table + i;
                size_t inbytesleft = 1, outbytesleft = 1;
                size_t ret_val = iconv(cd, &src, &inbytesleft, &dest, &outbytesleft);
                if (ret_val == size_t(-1))
                {
                    if (errno == EILSEQ)
                        table[i] = '?';
                    else
                    {
                        delete [] table;
                        table = NULL;
                        break;
                    }
                }
            }
            return;
        }

        unsigned int addavailable(const std::string &codepage, bool inc_bound = true)
        {
            io_iconv tmpio;

            if_found_in_hash(iter, codepage, name_hash)
            {
                //it already exists
                return iter->second;
            }
            else
            {
                /* wrong convertion, assuming default (0) */
                if  (((tmpio.in  = iconv_open(icodepage.c_str(), codepage.c_str())) == (iconv_t) - 1) ||
                        ((tmpio.out = iconv_open(codepage.c_str(), icodepage.c_str())) == (iconv_t) - 1))
                {
                    ServerInstance->Logs->Log("m_codepage.so", DEFAULT, "WARNING: wrong conversion between %s and %s. Assuming internal codepage!", icodepage.c_str(), codepage.c_str());
                }
                else /* right convertion, pushing it into the vector */
                {
                    tmpio.encoding = codepage;
                    makeitable(tmpio.in , tmpio.intable );
                    makeitable(tmpio.out, tmpio.outtable);
                    name_hash[codepage] = recode.size();
                    recode.push_back(tmpio);
                    if (inc_bound)
                        bound++;
                    return recode.size() - 1;
                }
            }

            return 0;
        }

        virtual void OnRehash(User* user)
        {
            SaveExisting();
            iClose();
            fd_hash.clear();
            port_hash.clear();
            name_hash.clear();
            recode.clear();
            icodepage = "";

            /* load the internal && default codepage */

            ConfigTagList tags = ServerInstance->Config->ConfTags("codepage");

            for(ConfigIter i = tags.first; i != tags.second; ++i)
            {
                ConfigTag* tag = i->second;

                std::string tmp;
                tmp = tag->getString("internal");
                if (!tmp.empty())
                {
                    icodepage = tmp;
                    break;
                }
            }

            if (icodepage.empty())
            {
                /* NO internal encoding set*/
                ServerInstance->Logs->Log("m_codepage", DEBUG, "WARNING: no internal encoding is set but module loaded");
                return;
            }

            ToUpper(icodepage);
            dcodepage = icodepage; /* set default codepage to the internal one by default ;) */

            for(ConfigIter i = tags.first; i != tags.second; ++i)
            {
                ConfigTag* tag = i->second;

                std::string tmp;
                tmp = tag->getString("default");
                if (!tmp.empty())
                {
                    dcodepage = tmp;
                    break;
                }
            }
            ToUpper(dcodepage);

            ServerInstance->Logs->Log("m_codepage", DEFAULT, "INFO: internal encoding is %s now, default is %s ", icodepage.c_str(), dcodepage.c_str());

            io_iconv tmpio;

            /* first we push a record for internal CP for no any convertion to be applied */
            tmpio.encoding = icodepage;
            tmpio.in = tmpio.out = (iconv_t) - 1;
            tmpio.intable = tmpio.outtable = NULL;
            name_hash[icodepage] = 0;
            recode.push_back(tmpio);
            bound = 1;

            /* list of available encodings */

            for(ConfigIter i = tags.first; i != tags.second; ++i)
            {
                ConfigTag* tag = i->second;

                std::string tmp;
                tmp = tag->getString("available");
                if (!tmp.empty())
                {
                    irc::commasepstream css(tmp.c_str());
                    std::string tok;
                    while(css.GetToken(tok))
                    {
                        ToUpper(tok);
                        addavailable(tok);
                    }
                    break;
                }
            }

            /* setting up encodings on ports */

            ConfigTagList binds = ServerInstance->Config->ConfTags("bind");

            for(ConfigIter i = binds.first; i != binds.second; ++i)
            {
                ConfigTag* tag = i->second;

                std::string type, codepage, port, addr;
                int recodeindex = 0;

                type    = tag->getString("type");
                if (type != "clients")
                {
                    continue;   /* oh, that's a server port, sorry, skipping :( */
                }

                codepage = tag->getString("codepage");
                port = tag->getString("port");
                addr = tag->getString("address");

                if (codepage.empty()) /* no encoding specified explicitly. assuming default */
                {
                    codepage = dcodepage;
                }
                else
                {
                    ToUpper(codepage);
                }

                recodeindex = addavailable(codepage);
                irc::portparser portrange(port, false);
                long portno = -1;
                while ((portno = portrange.GetToken()))
                {
                    port_hash[portno] = recodeindex;
                    ServerInstance->Logs->Log("m_codepage.so", DEFAULT, "INFO: adding %s encoding on the port %ld", recode[port_hash[portno]].encoding.c_str(), portno);
                }

            }

            HookExisting();
        }

        virtual void OnStreamSocketClose(StreamSocket* user)
        {
            int fd = user->GetFd();
            fd_hash.erase(fd);

            if_found_in_hash(iter2, fd, io_hash)
            {
                iter2->second->OnStreamSocketClose(user);
            }
            io_hash.erase(fd);
            buffer_hash.erase(fd);
            buffer_hash_write.erase(fd);
        }

        virtual void OnStreamSocketConnect(StreamSocket* user)
        {
            int fd = user->GetFd();

            if_found_in_hash(iter2, fd, io_hash)
            {
                iter2->second->OnStreamSocketConnect(user);
            }
        }
        virtual void OnStreamSocketAccept(StreamSocket* user, irc::sockets::sockaddrs* client, irc::sockets::sockaddrs* server)
        {
            int fd = user->GetFd();

            if_found_in_hash(iter, server->port(), port_hash)
            fd_hash[fd] = iter->second;

            if_found_in_hash(iter2, fd, io_hash)
            {
                iter2->second->OnStreamSocketAccept(user, client, server);
            }
        }

        virtual void OnHookIO(StreamSocket* user, ListenSocket* lsb)
        {
            /* Hook the user with our module... (and save his/her/its (that may be also a bot ;) ) ->IOHook ) */
            if (user->GetIOHook())
            {
                io_hash[user->GetFd()] = user->GetIOHook();
            }
            ModifyIOHook(*user, this);
        }

        size_t i_convert(iconv_t cd, char* dest, char* src, int countin, int countout, bool omiteinval = true, int fd = -1)
        {

            size_t ret_val = (size_t)0;
            size_t inbytesleft = countin, outbytesleft = countout;
            char* src1 = src;
            char* dest1 = dest;
            if (cd != (iconv_t) - 1)
            {
                for(; inbytesleft && !((ret_val == (size_t) - 1) && ((errno == E2BIG) || (errno == EINVAL))); --inbytesleft, ++src1)
                {
                    ret_val = iconv(cd, &src1, &inbytesleft, &dest1, &outbytesleft);
                    if (!inbytesleft) break;
                }

                /* Saving incomplete character. let's be paranoid, (inbytesleft<4) */
                if ((errno == EINVAL) && (!omiteinval) && (inbytesleft < 4))
                {
                    io_buffer tmpio_b;
                    memcpy(tmpio_b.buffer, src1, inbytesleft);
                    tmpio_b.count = inbytesleft;
                    buffer_hash[fd] = tmpio_b;
                }

                return countout - outbytesleft;
            }
            memcpy(dest, src, countin);
            return countin;
        }

        virtual int OnStreamSocketRead(StreamSocket* u, std::string& recvq)
        {

            io_iconv tmpio;
            int result = 1;
            int fd = u->GetFd();

            if_found_in_hash(iter2, fd, io_hash)
            {
                result = iter2->second->OnStreamSocketRead(u, recvq);
            }
            else
            {
                result = raw_read(u, recvq);
            }
            int count = recvq.length();

            if_found_in_hash(iter, fd, fd_hash)
            tmpio = recode[iter->second];
            else
                tmpio.in = (iconv_t) - 1;

            if (result <= 0)
                return result;

            char * outbuffer = new char[count * 4 + 4];
            size_t cnt = count;

            if (tmpio.in != (iconv_t) - 1)
            {
                /* translating encodings here */
                char * tmpbuffer = new char[count + 4];
                char * writestart = tmpbuffer;

                int delta = 0;
                if_found_in_hash(iter3, fd, buffer_hash)
                {
                    delta = iter3->second.count;
                    memcpy(tmpbuffer, iter3->second.buffer, delta);
                    writestart += delta;
                    buffer_hash.erase(iter3);
                }

                const char* buffer = recvq.c_str();
                memcpy(writestart, buffer, count);

                if (tmpio.intable != NULL)
                {
                    itableconvert(tmpio.intable, outbuffer, tmpbuffer, count + delta);
                }
                else
                {
                    cnt = i_convert(tmpio.in, outbuffer, tmpbuffer, count + delta, count * 4 + 4, false, fd);

                }
                delete [] tmpbuffer;
                recvq.assign(outbuffer, cnt);
            }

            return result;

        }

        int raw_read(StreamSocket* sock, std::string &recvq)
        {
            char* ReadBuffer = ServerInstance->GetReadBuffer();
            int n = ServerInstance->SE->Recv(sock, ReadBuffer, ServerInstance->Config->NetBufferSize, 0);
            if (n == ServerInstance->Config->NetBufferSize)
            {
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_FAST_READ | FD_ADD_TRIAL_READ);
                recvq.assign(ReadBuffer, n);
            }
            else if (n > 0)
            {
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_FAST_READ);
                recvq.assign(ReadBuffer, n);
            }
            else if (n == 0)
            {
                sock->SetError("Connection closed");
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_NO_READ | FD_WANT_NO_WRITE);
                return -1;
            }
            else if (SocketEngine::IgnoreError())
            {
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_FAST_READ | FD_READ_WILL_BLOCK);
                return 0;
            }
            else if (errno == EINTR)
            {
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_FAST_READ | FD_ADD_TRIAL_READ);
                return 0;
            }
            else
            {
                sock->SetError(SocketEngine::LastError());
                ServerInstance->SE->ChangeEventMask(sock, FD_WANT_NO_READ | FD_WANT_NO_WRITE);
                return -1;
            }
            return 1;
        }

        virtual int OnStreamSocketWrite(StreamSocket* u, std::string& sendq)
        {
            int fd = u->GetFd();

            io_iconv tmpio;
            std::string tmp_sendq;

            if_found_in_hash(iter3, fd, buffer_hash_write)
            {
                tmp_sendq.assign(iter3->second);
                buffer_hash_write.erase(iter3);
            }
            else
            {
                if_found_in_hash(iter, fd, fd_hash)
                tmpio = recode[iter->second];
                else
                    tmpio.out = (iconv_t) - 1;

                int count = sendq.length();
                size_t cnt = count;
                char * tmpbuffer = new char[count * 4 + 1]; /* assuming UTF-8 is 4 chars wide max. */
                const char* buffer = sendq.c_str();
                if (tmpio.out != (iconv_t) - 1)
                {
                    /* translating encodings here */
                    if (tmpio.outtable != NULL)
                    {
                        itableconvert(tmpio.outtable, tmpbuffer, buffer, count);
                        tmpbuffer[count] = 0;
                    }
                    else
                        cnt = i_convert(tmpio.out, tmpbuffer, (char *)buffer, count, count * 4);
                }
                else
                {
                    memcpy(tmpbuffer, buffer, count);
                    tmpbuffer[count] = 0;
                }

                tmp_sendq.assign(tmpbuffer, cnt);
                delete[] tmpbuffer;
            }

            int tmpres = 0;
            if_found_in_hash(iter2, fd, io_hash)
            {
                tmpres = iter2->second->OnStreamSocketWrite(u, tmp_sendq);
            }
            else
            {
                //ServerInstance->SE->Send(u, sendq.c_str(), sendq.length(), 0);
                ServerInstance->Logs->Log("m_codepage.so", DEFAULT, "<<<%s", tmp_sendq.c_str());
                tmpres = raw_write(u, tmp_sendq);
            }

            if (tmpres != 0)
                return tmpres;

            //saving unsent data
            buffer_hash_write[fd] = tmp_sendq;
            return 0;
        }

        int raw_write(StreamSocket* user, std::string& front)
        {
            int fd = user->GetFd();
            if (!user->getError().empty() || fd < 0 || fd == INT_MAX)
            {
                ServerInstance->Logs->Log("SOCKET", DEBUG, "DoWrite on errored or closed socket");
                return -1;
            }

            int rv = -1;
            int itemlen = front.length();
            rv = ServerInstance->SE->Send(user, front.data(), itemlen, 0);
            if (rv == 0)
            {
                user->SetError("Connection closed");
                return -1;
            }
            else if (rv < 0)
            {
                if (errno == EINTR || SocketEngine::IgnoreError())
                {
                    ServerInstance->SE->ChangeEventMask(user, FD_WANT_FAST_WRITE | FD_WRITE_WILL_BLOCK);
                    return 0;
                }
                else
                {
                    user->SetError(SocketEngine::LastError());
                    return -1;
                }
            }
            else if (rv < itemlen)
            {
                ServerInstance->SE->ChangeEventMask(user, FD_WANT_FAST_WRITE | FD_WRITE_WILL_BLOCK);
                front = front.substr(rv);
                return 0;
            }
            front.clear();
            return 1;
        }

        virtual void OnCleanup(int target_type, void* item)
        {
            if(target_type == TYPE_USER)
            {
                if_not_local_user(user, (User*)item)
                return;

                if(user->eh.GetIOHook() == this)
                {
                    if_found_in_hash(iter, user->eh.GetFd(), io_hash)
                    {
                        ModifyIOHook(user->eh, iter->second);
                    }
                    else
                    {
                        user->eh.DelIOHook();
                    }
                }
            }
        }

        void Prioritize()
        {
            for (unsigned int i = 0; i < 3; ++i)
            {
                Module* mod = ServerInstance->Modules->Find(modulenames[i]);
                if (mod == NULL)
                {
                    continue;
                }
                for (unsigned int j = 0; j < sizeof(eventlist) / sizeof(Implementation); ++j)
                {
                    ServerInstance->Modules->SetPriority(this, eventlist[j], PRIORITY_AFTER, &mod);
                }
            }
        }

        virtual void On005Numeric(std::string& output)
        {
            output += " CODEPAGES";
        }

        void OnUnloadModule  (Module* mod)
        {
            std::vector<User *> cleanup;
            cleanup.clear();
            for (hash_io::iterator iter = io_hash.begin(); iter != io_hash.end(); ++iter)
            {
                if (iter->second == mod)
                {
                    User* u = dynamic_cast<User*>(ServerInstance->SE->GetRef(iter->first));
                    if_not_local_user(user, u)
                    continue;
                    ModifyIOHook(user->eh, mod);
                    cleanup.push_back(user);
                }
            }

            for(std::vector<User *>::iterator iter2 = cleanup.begin(); iter2 != cleanup.end(); ++iter2)
            {
                if_not_local_user(user, *iter2)
                continue;

                int fd = user->eh.GetFd();
                mod->OnCleanup(TYPE_USER, (* iter2));
                io_hash.erase(fd);
                /* Let's handle XML Socket etc. properly */
                if ((*iter2)->quitting)
                {
                    fd_hash.erase(fd);
                    buffer_hash.erase(fd);
                    buffer_hash_write.erase(fd);
                }
                else
                    user->eh.DelIOHook();
                user->eh.AddIOHook(this);
            }

            /* give us back our users!!! >:( */
            if (mod != this)
                for (hash_common::iterator iter = fd_hash.begin(); iter != fd_hash.end(); ++iter)
                {
                    User* u = dynamic_cast<User*>(ServerInstance->SE->GetRef(iter->first));
                    if_not_local_user(user, u)
                    continue;
                    ModifyIOHook(user->eh, this);
                    /* Welcome back ;) */
                }

        }

        void iClose()
        {
            for (std::vector<io_iconv>::iterator iter = recode.begin(); iter != recode.end(); iter++)
            {
                if ((*iter).in != (iconv_t) - 1)
                {
                    iconv_close((*iter).in);
                    if ((*iter).intable != NULL)
                        delete [] (*iter).intable;
                }
                if ((*iter).out != (iconv_t) - 1)
                {
                    iconv_close((*iter).out);
                    if ((*iter).outtable != NULL)
                        delete[](*iter).outtable;
                }
            }
        }

        virtual ~ModuleCodepage()
        {
            for (hash_io::iterator iter = io_hash.begin(); iter != io_hash.end(); iter++)
            {
                User* u = dynamic_cast<User*>(ServerInstance->SE->GetRef(iter->first));
                if (u == NULL)
                    continue;
                if_not_local_user(user, u)
                continue;
                ModifyIOHook(user->eh, iter->second);
            }
            iClose();
        }

        virtual Version GetVersion()
        {
            return Version("$Id$", VF_OPTCOMMON);
        }

};

MODULE_INIT(ModuleCodepage)

