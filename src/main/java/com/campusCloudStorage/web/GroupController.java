package com.campusCloudStorage.web;


import com.campusCloudStorage.dto.GroupFileShareItem;
import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.entity.UserGroup;
import com.campusCloudStorage.enums.*;
import com.campusCloudStorage.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;


@Controller
@RequestMapping("/group")
public class GroupController {

    @Autowired
    private GroupMemberService groupMemberService;

    @Autowired
    private UserGroupService userGroupService;

    @Autowired
    private GroupFileShareService groupFileShareService;

    @RequestMapping(value="/{uId}",method= RequestMethod.POST)
    public String generalList(@PathVariable("uId") int uId, HttpServletRequest request, Model model) {
        HttpSession session=request.getSession();
        int rootDir=(int)session.getAttribute("rootDir");
        int recyclebin=(int)session.getAttribute("recyclebin");

        List<UserGroup> ownedGroupList=userGroupService.selectOwnedGroups(uId);
        List<UserGroup> joinedGroupList=userGroupService.selectJoinedGroups(uId);

        model.addAttribute("uId",uId);
        model.addAttribute("rootDir",rootDir);
        model.addAttribute("recyclebin",recyclebin);
        model.addAttribute("ownedGroupList",ownedGroupList);
        model.addAttribute("joinedGroupList",joinedGroupList);
        return "group";
    }

    @RequestMapping(value="/{uId}/{gId}",method= RequestMethod.POST)
    public String detailList(@PathVariable("uId") int uId, @PathVariable("gId") int gId, HttpServletRequest request, Model model) {
        HttpSession session=request.getSession();
        int rootDir=(int)session.getAttribute("rootDir");
        int recyclebin=(int)session.getAttribute("recyclebin");

        User owner = userGroupService.selectOwner(gId);
        List<User> memberList=userGroupService.selectMembers(gId);
        List<GroupFileShareItem> groupFileShareList = groupFileShareService.getGroupSharedFilesByGId(gId);
        List<User>unpermittedMemberList=groupMemberService.selectUnpermittedMembers(gId);

        model.addAttribute("uId",uId);
        model.addAttribute("gId",gId);
        model.addAttribute("owner",owner);
        model.addAttribute("rootDir",rootDir);
        model.addAttribute("recyclebin",recyclebin);

        model.addAttribute("groupFileShareList",groupFileShareList);
        model.addAttribute("memberList",memberList);
        model.addAttribute("unpermittedMemberList",unpermittedMemberList);

        return "groupdetail";
    }

    @RequestMapping(value = "/{uId}/{gId}/{memberId}/permit",method = RequestMethod.POST)
    public String permit(@PathVariable("uId") int uId, @PathVariable("gId") int gId, @PathVariable("memberId") int memberId, RedirectAttributes attributes){
        groupMemberService.permitMemberRequest(gId,memberId);

        attributes.addFlashAttribute("uId",uId);
        return "forward:/group/"+uId+"/"+gId;
    }

    @RequestMapping(value = "/{uId}/{gId}/{memberId}/refuse",method = RequestMethod.POST)
    public String refuseGroupRequest(@PathVariable("uId") int uId, @PathVariable("gId") int gId, @PathVariable("memberId") int memberId, RedirectAttributes attributes){
        groupMemberService.refuseGroupRequest(gId,memberId);
        attributes.addFlashAttribute("uId",uId);
        return "forward:/group/"+uId+"/"+gId;
    }

    @RequestMapping(value = "/{uId}/{gId}/{memberId}/delete",method = RequestMethod.POST)
    public String deleteGroupMember(@PathVariable("uId") int uId, @PathVariable("gId") int gId, @PathVariable("memberId") int memberId, RedirectAttributes attributes){
        groupMemberService.deleteMember(gId,memberId);
        attributes.addFlashAttribute("uId",uId);

        //uId!=memberId时，为群主操作，踢出成员。反之则为群员主动退出。两个返回的页面不一样
        if(uId!=memberId)
            return "forward:/group/"+uId+"/"+gId;
        else
            return "forward:/group/"+uId;
    }

    @RequestMapping(value = "/{uId}/{gId}/search",method= RequestMethod.POST,produces = "text/html;charset=UTF-8")
    @ResponseBody
    public String search(@PathVariable("uId") int uId, @PathVariable("gId") int gId){
        StringBuilder result=new StringBuilder();

        UserGroup userGroup = userGroupService.selectByPrimaryKey(gId);
        if(userGroup==null){
            result.append(GroupRequestStateEnum.NO_GROUP.getStateInfo());
            return result.toString();
        }

        result.append("群组ID：");
        result.append(gId);
        result.append(" 群组名：");
        result.append(userGroup.getName());
        result.append("<button class='btn btn-default' id='group_request_btn' type='submit' g_id='");
        result.append(gId);
        result.append("'>申请加入</button>");

        return result.toString();
    }

    @RequestMapping(value = "/{uId}/{gId}/request",method = RequestMethod.POST)
    public String request(@PathVariable("uId") int uId, @PathVariable("gId") int gId, RedirectAttributes attributes, Model model){
        GroupRequestStateEnum groupRequestState = groupMemberService.sendJoinRequests(gId,uId);

        model.addAttribute("msg",groupRequestState.getStateInfo());
        attributes.addFlashAttribute("uId",uId);
        return "forward:/group/"+uId;
    }

    @RequestMapping(value = "/{uId}/addgroup",method = RequestMethod.POST)
    public String addGroup(@PathVariable("uId") int uId,UserGroup userGroup,RedirectAttributes attributes, Model model){
        if(userGroup!=null){
            userGroup.setBuilderId(uId);
        }
        CreateStateEnum createState = userGroupService.createUserGroup(userGroup);

        model.addAttribute("msg",createState.getStateInfo());
        attributes.addFlashAttribute("uId",uId);
        return "forward:/group/"+uId;
    }

    @RequestMapping(value = "/{uId}/{gId}/deletegroup",method = RequestMethod.POST)
    public String deleteGroup(@PathVariable("uId") int uId, @PathVariable("gId") int gId, RedirectAttributes attributes, Model model){
        DeleteStateEnum deleteState = userGroupService.deleteUserGroup(uId, gId);

        model.addAttribute("msg",deleteState.getStateInfo());
        attributes.addFlashAttribute("uId",uId);
        return "forward:/group/"+uId;
    }

    @RequestMapping(value = "/{uId}/{gId}/{fId}/groupshare",method = RequestMethod.POST)
    public String groupShareFile(@PathVariable("uId") int uId, @PathVariable("gId") int gId, @PathVariable("fId") int fId, String remark,
                                 HttpServletRequest request, RedirectAttributes attributes, Model model){
        ShareStateEnum shareState = groupFileShareService.insertGroupSharedFile(uId,gId,fId,remark);

        model.addAttribute("msg",shareState.getStateInfo());
        attributes.addFlashAttribute("uId",uId);

        HttpSession session = request.getSession();
        int currentDir=(int) session.getAttribute("currentDir");
        return "forward:/home/"+currentDir;
    }

    @RequestMapping(value = "/{uId}/{gId}/{fId}/deletegroupshare",method = RequestMethod.POST)
    public String deleteGroupShareFile(@PathVariable("uId") int uId, @PathVariable("gId") int gId, @PathVariable("fId") int fId, Model model){
        DeleteStateEnum deleteState = groupFileShareService.deleteByGIdAndFId(gId,fId);

        model.addAttribute("msg",deleteState.getStateInfo());
        return "forward:/group/"+uId + "/" + gId;
    }
}
