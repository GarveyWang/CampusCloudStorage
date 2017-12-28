package com.campusCloudStorage.web;


import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.enums.FriendRequestStateEnum;
import com.campusCloudStorage.service.UserFriendService;
import com.campusCloudStorage.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;


@Controller
@RequestMapping("/friend")
public class FriendController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserFriendService userFriendService;

    @RequestMapping(value="/{uId}",method= RequestMethod.POST)
    public String list(@PathVariable("uId") int uId, HttpServletRequest request, Model model) {
        HttpSession session=request.getSession();
        int rootDir=(int)session.getAttribute("rootDir");
        int recyclebin=(int)session.getAttribute("recyclebin");

        List<User>friendList=userFriendService.selectPermittedFriendsByUId(uId);
        List<User>unpermittedFriendList=userFriendService.selectFriendRequestByUId(uId);


        model.addAttribute("uId",uId);
        model.addAttribute("rootDir",rootDir);
        model.addAttribute("recyclebin",recyclebin);
        model.addAttribute("friendList",friendList);
        model.addAttribute("unpermittedFriendList",unpermittedFriendList);

        return "friend";
    }

    @RequestMapping(value = "/{uId}/{friendId}/agree",method = RequestMethod.POST)
    public String agree(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId, RedirectAttributes attributes){
        userFriendService.permitFriendRequest(uId,friendId);

        attributes.addFlashAttribute("uId",uId);
        return "forward:/friend/"+uId;
    }

    @RequestMapping(value = "/{uId}/{friendId}/delete",method = RequestMethod.POST)
    public String delete(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId, RedirectAttributes attributes){
        userFriendService.deleteFriend(uId,friendId);
        attributes.addFlashAttribute("uId",uId);
        return "forward:/friend/"+uId;
    }

    @RequestMapping(value = "/{uId}/{friendId}/search",method= RequestMethod.POST,produces = "text/html;charset=UTF-8")
    @ResponseBody
    public String search(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId){
        StringBuilder result=new StringBuilder();

        if(uId==friendId){
            result.append(FriendRequestStateEnum.SELF_REQUEST.getStateInfo());
            return result.toString();
        }

        User friend = userService.selectByPrimaryKey(friendId);
        if(friend==null){
            result.append(FriendRequestStateEnum.NO_USER.getStateInfo());
            return result.toString();
        }
        result.append("用户ID：");
        result.append(friendId);
        result.append("   用户名：");
        result.append(friend.getName());
        result.append("<button class='btn btn-default' id='friend_request_btn' type='submit' friend_id='");
        result.append(friendId);
        result.append("'>添加好友</button>");

        return result.toString();
    }

    @RequestMapping(value = "/{uId}/{friendId}/request",method = RequestMethod.POST)
    public String request(@PathVariable("uId") int uId, @PathVariable("friendId") int friendId, RedirectAttributes attributes, Model model){
        FriendRequestStateEnum friendRequestState = userFriendService.sendFriendRequest(uId,friendId);

        model.addAttribute("msg",friendRequestState.getStateInfo());
        attributes.addFlashAttribute("uId",uId);
        return "forward:/friend/"+uId;
    }

}
