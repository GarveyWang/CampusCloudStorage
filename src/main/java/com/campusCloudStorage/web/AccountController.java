package com.campusCloudStorage.web;

import com.campusCloudStorage.entity.User;
import com.campusCloudStorage.enums.LoginStateEnum;
import com.campusCloudStorage.enums.RegisterStateEnum;
import com.campusCloudStorage.service.UserService;
import com.campusCloudStorage.web.security.RSA;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


@Controller
@RequestMapping("/account")
public class AccountController {

    @Autowired
    private UserService userService;

    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public String login(){
        return "login";
    }

    @RequestMapping(value="/login",method= RequestMethod.POST)
    public String login(User user, HttpServletRequest request, RedirectAttributes attributes, RedirectAttributesModelMap modelMap) {
        user.setPassword(RSA.getInstance().decryptByPrivateKey(user.getPassword()));
        
        LoginStateEnum loginState=userService.validate(user);
        if(loginState!=LoginStateEnum.SUCCESS){
            return "login";
        }

        int uId=user.getuId();
        User userFromDB=userService.selectByPrimaryKey(uId);
        int rootDir=userFromDB.getRootDir();

        HttpSession session=request.getSession();
        session.setAttribute("uId",uId);
        session.setAttribute("rootDir",userFromDB.getRootDir());
        session.setAttribute("recyclebin",userFromDB.getRecyclebin());
        modelMap.addFlashAttribute("uId",uId);
        attributes.addFlashAttribute("uId",uId);
        return "forward:/home/"+rootDir;
    }

    @RequestMapping(value = "/register",method = RequestMethod.GET)
    public String register(){
        return "register";
    }

    @RequestMapping(value="/register",method= RequestMethod.POST)
    public String register(User user,Model model) {
        RegisterStateEnum registerState = userService.register(user);
        model.addAttribute("msg",registerState.getStateInfo());
        if(registerState==RegisterStateEnum.SUCCESS){
            return "login";
        }
        model.addAttribute("user",user);
        return "register";
    }

}
