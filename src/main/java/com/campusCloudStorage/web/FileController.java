package com.campusCloudStorage.web;


import com.campusCloudStorage.dto.FriendFileShareItem;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.enums.ShareStateEnum;
import com.campusCloudStorage.service.FileHeaderService;
import com.campusCloudStorage.service.UserFileShareService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.URLEncoder;
import java.util.Date;
import java.util.List;

@RequestMapping("file")
@Controller
public class FileController {

    @Resource
    private FileHeaderService fileHeaderService;

    @Resource
    private UserFileShareService userFileShareService;

    @RequestMapping(value="/upload",method= RequestMethod.POST)
    public String fileUpload(MultipartFile file, HttpServletRequest request) throws IOException {
        HttpSession session=request.getSession();
        int uId=(int)session.getAttribute("uId");
        int currentDir = (int)session.getAttribute("currentDir");

        String path = request.getServletContext().getRealPath(String.valueOf(uId));
        String fileName = String.valueOf(new Date().hashCode())+file.getOriginalFilename();
        File dir = new File(path,fileName);
        if(!dir.exists()){
            dir.mkdirs();
        }

        file.transferTo(dir);

        FileHeader fileHeader=new FileHeader();
        fileHeader.setName(file.getOriginalFilename());
        fileHeader.setSize((int)file.getSize());
        fileHeader.setParent(currentDir);
        fileHeader.setuId(uId);
        fileHeader.setPath(dir.toString());
        fileHeaderService.createFileHeader(fileHeader);

        return "forward:/home/"+currentDir;
    }


    @RequestMapping(value="/{fId}/download",method = RequestMethod.POST)
    public void fileDownload(@PathVariable("fId") int fId, HttpServletResponse response) throws Exception{
        FileHeader fileHeader=fileHeaderService.getFileHeaderById(fId);
        String path = fileHeader.getPath();
        InputStream bis = new BufferedInputStream(new FileInputStream(new File(path)));

        String fileName = fileHeader.getName();
        fileName = URLEncoder.encode(fileName,"UTF-8");
        //设置文件下载头
        response.addHeader("Content-Disposition", "attachment;filename=" + fileName);
        //1.设置文件ContentType类型，这样设置，会自动判断下载文件类型
        response.setContentType("multipart/form-data");
        BufferedOutputStream out = new BufferedOutputStream(response.getOutputStream());
        int len = 0;
        while((len = bis.read()) != -1){
            out.write(len);
            out.flush();
        }
        out.close();
    }

    @RequestMapping(value="/{fId}/remove",method = RequestMethod.POST)
    public String fileRemove(@PathVariable("fId") int fId, HttpServletRequest request){
        HttpSession session=request.getSession();
        int recyclebin=(int)session.getAttribute("recyclebin");

        FileHeader fileHeader= fileHeaderService.getFileHeaderById(fId);
        fileHeader.setParent(recyclebin);
        fileHeaderService.updateFileHeader(fileHeader);

        int currentDir = (int)session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="/{fId}/delete",method = RequestMethod.POST)
    public String fileDelete(@PathVariable("fId") int fId, HttpServletRequest request){
        HttpSession session=request.getSession();
        int currentDir = (int)session.getAttribute("currentDir");
        fileHeaderService.deleteFileHeader(fId);
        return "forward:/recyclebin/"+currentDir;
    }

    @RequestMapping(value="/{uId}/{friendId}/friendshare",method = RequestMethod.POST)
    public String friendSharePage(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId, HttpServletRequest request, Model model){
        HttpSession session=request.getSession();
        int rootDir=(int)session.getAttribute("rootDir");
        int recyclebin=(int)session.getAttribute("recyclebin");

        List<FriendFileShareItem> mySharedList=userFileShareService.selectSharedFilesByUId(uId,friendId);
        List<FriendFileShareItem> friendSharedList=userFileShareService.selectSharedFilesByUId(friendId,uId);

        model.addAttribute("uId",uId);
        model.addAttribute("rootDir",rootDir);
        model.addAttribute("recyclebin",recyclebin);
        model.addAttribute("friendId",friendId);
        model.addAttribute("mySharedList",mySharedList);
        model.addAttribute("friendSharedList",friendSharedList);

        return "friendshare";
    }

    @RequestMapping(value="/{uId}/{friendId}/{fId}/friendshare",method = RequestMethod.POST)
    public String addFriendShareFile(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId,@PathVariable("fId") int fId, String remark, HttpServletRequest request, Model model){
        ShareStateEnum shareState=userFileShareService.shareFileWithFriend(uId,friendId,fId,remark);

        model.addAttribute("msg",shareState.getStateInfo());
        HttpSession session=request.getSession();
        int currentDir=(int)session.getAttribute("currentDir");

        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="/{uId}/{friendId}/{fId}/deletefriendshare",method = RequestMethod.POST)
    public String deleteFriendShareFile(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId,@PathVariable("fId") int fId, HttpServletRequest request, Model model){
        userFileShareService.deleteByPrimaryKey(uId,friendId,fId);

        HttpSession session=request.getSession();
        int currentDir=(int)session.getAttribute("currentDir");

        model.addAttribute("msg","取消成功");
        return "forward:/file/"+uId+"/"+friendId+"/friendshare";
    }
}
