package com.campusCloudStorage.web;

import com.campusCloudStorage.entity.*;
import com.campusCloudStorage.enums.CreateStateEnum;
import com.campusCloudStorage.enums.UpdateStateEnum;
import com.campusCloudStorage.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;

@Controller
@RequestMapping("/home")
public class HomeController {

    @Autowired
    private FileHeaderService fileHeaderService;

    @Autowired
    private DirService dirService;

    @Autowired
    private UserService userService;

    @Autowired
    private UserFriendService userFriendService;

    @Autowired
    private UserGroupService userGroupService;

    @RequestMapping(value="/{dId}",method= RequestMethod.POST)
    public String list(@PathVariable("dId")int dId, HttpServletRequest request, Model model) {
        HttpSession session=request.getSession();
        int uId=(int)session.getAttribute("uId");
        int rootDir=(int)session.getAttribute("rootDir");
        int recyclebin=(int)session.getAttribute("recyclebin");

        User user=userService.selectByPrimaryKey(uId);

        Dir dir=dirService.getDirById(dId);
        List<Dir> dirList=dirService.getFirstChildrenDirs(dId);
        List<FileHeader> fileHeaderList=dirService.getFirstChildrenFileHeaders(dId);
        List<Dir> pathList=dirService.getPathList(dir);

        List<Dir> moveList=dirService.getFirstChildrenDirs(rootDir);

        List<User> friendList=userFriendService.selectPermittedFriendsByUId(uId);
        List<UserGroup> groupList=userGroupService.selectOwnedAndJoinedGroups(uId);

        model.addAttribute("uId",uId);
        model.addAttribute("userName",user.getName());
        model.addAttribute("currentDir",dId);
        model.addAttribute("rootDir",rootDir);
        model.addAttribute("recyclebin",recyclebin);

        model.addAttribute("friendList",friendList);
        model.addAttribute("dirList",dirList);
        model.addAttribute("fileHeaderList",fileHeaderList);
        model.addAttribute("pathList",pathList);
        model.addAttribute("moveList",moveList);
        model.addAttribute("groupList",groupList);

        session.setAttribute("currentDir",dId);
        return "home";
    }


    @RequestMapping(value="/{dId}/dir/add",method= RequestMethod.POST)
    public String addDir(@PathVariable("dId")int dId, Dir dir, RedirectAttributesModelMap modelMap) {
        dir.setParent(dId);
        CreateStateEnum createState=dirService.createDir(dir);
        modelMap.addFlashAttribute("msg",createState.getStateInfo());
        return "forward:/home/"+dId;
    }

    @RequestMapping(value="/{dId}/dir/remove",method= RequestMethod.POST)
    public String removeDir(@PathVariable("dId")int dId, HttpServletRequest request) {
        HttpSession session=request.getSession();
        int recyclebin=(int)session.getAttribute("recyclebin");

        Dir dir = dirService.getDirById(dId);
        dir.setParent(recyclebin);
        dirService.updateDir(dir);

        int currentDir = (int)session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="/{dId}/dir/rename",method= RequestMethod.POST)
    public String renameDir(@PathVariable("dId")int dId, String name, HttpServletRequest request, RedirectAttributesModelMap modelMap) {
        Dir dir=dirService.getDirById(dId);
        dir.setName(name);
        UpdateStateEnum updateState = dirService.updateDir(dir);

        modelMap.addFlashAttribute("msg",updateState.getStateInfo());

        HttpSession session=request.getSession();
        int currentDir = (int)session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="/{dId}/dir/{newParentId}/move",method= RequestMethod.POST)
    public String moveDir(@PathVariable("dId")int dId, @PathVariable("newParentId")int newParentId,
                            HttpServletRequest request, RedirectAttributesModelMap modelMap) {
        Dir dir=dirService.getDirById(dId);
        dir.setParent(newParentId);
        UpdateStateEnum updateState = dirService.updateDir(dir);

        modelMap.addFlashAttribute("msg",updateState.getStateInfo());

        HttpSession session=request.getSession();
        int currentDir = (int)session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="/{fId}/file/{newParentId}/move",method= RequestMethod.POST)
    public String moveFile(@PathVariable("fId")int fId, @PathVariable("newParentId")int newParentId,
                          HttpServletRequest request, RedirectAttributesModelMap modelMap) {
        FileHeader fileHeader= fileHeaderService.getFileHeaderById(fId);
        fileHeader.setParent(newParentId);
        UpdateStateEnum updateState = fileHeaderService.updateFileHeader(fileHeader);

        modelMap.addFlashAttribute("msg",updateState.getStateInfo());

        HttpSession session=request.getSession();
        int currentDir = (int)session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value="{srcId}/dir/{dId}/enter",method= RequestMethod.POST,produces = "text/html;charset=UTF-8")
    @ResponseBody
    public String enterDir(@PathVariable("srcId") int srcId, @PathVariable("dId")int dId, String moveType) {
        Dir dir=dirService.getDirWithFirstChildrenById(dId);

        StringBuilder responseText=new StringBuilder();
        if(moveType.equals("dir")){
            responseText.append("<div class=\"btn-group\"><button class=\"btn btn-default\" id=\"dir_move_btn\" d_id=\"");
        }else {
            responseText.append("<div class=\"btn-group\"><button class=\"btn btn-default\" id=\"file_move_btn\" d_id=\"");
        }

        responseText.append(dId);
        responseText.append("\">移入</button>");
        if(dir.getParent()!=null){
            responseText.append("<button class=\"btn btn-default\" id=\"");
            if(moveType.equals("dir")){
                responseText.append("dir_move_back_btn");
            }else {
                responseText.append("file_move_back_btn");
            }
            responseText.append("\" d_id=\"");
            responseText.append(dir.getParent());
            responseText.append("\">返回上一级</button>");
        }

        responseText.append("<button type=\"button\" id=\"");
        if(moveType.equals("dir")){
            responseText.append("dir_move_form_close_btn");
        }else {
            responseText.append("file_move_form_close_btn");
        }
        responseText.append("\" class=\"btn btn-default\">取消</button></div>");

        List<Dir>childrenDirList=dir.getChildrenDirList();
        for (Dir child:childrenDirList){
            if(moveType.equals("dir") && child.getdId()==srcId){
                continue;
            }
            if(moveType.equals("dir")){
                responseText.append("<li class=\"list-group-item\"><button class=\"btn btn-default dir_move_enter_btn\" d_id=\"");
            }
            else {
                responseText.append("<li class=\"list-group-item\"><button class=\"btn btn-default file_move_enter_btn\" d_id=\"");
            }
            responseText.append(child.getdId());
            responseText.append("\">打开</button>");
            responseText.append(child.getName());
            responseText.append("</li>");
        }
        return responseText.toString();
    }

}
