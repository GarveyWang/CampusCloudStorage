package com.campusCloudStorage.service.impl;

import com.campusCloudStorage.dao.FileHeaderDao;
import com.campusCloudStorage.dao.UserFileShareDao;
import com.campusCloudStorage.dto.FriendFileShareItem;
import com.campusCloudStorage.entity.FileHeader;
import com.campusCloudStorage.entity.UserFileShare;
import com.campusCloudStorage.enums.DeleteStateEnum;
import com.campusCloudStorage.enums.ShareStateEnum;
import com.campusCloudStorage.service.UserFileShareService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service("userFileShareService")
public class UserFileShareServiceImpl implements UserFileShareService{

    @Resource
    private UserFileShareDao userFileShareDao;

    @Resource
    private FileHeaderDao fileHeaderDao;

    @Override
    public List<FriendFileShareItem> selectSharedFilesByUId(int fromId, int toId) {
        List<UserFileShare> userFileShareList=userFileShareDao.selectByUId(fromId,toId);
        List<FriendFileShareItem> fileShareList=new ArrayList<FriendFileShareItem>();
        for (UserFileShare userFileShare: userFileShareList) {
            FriendFileShareItem shareItem=new FriendFileShareItem();
            FileHeader fileHeader= fileHeaderDao.selectByPrimaryKey(userFileShare.getfId());
            if(fileHeader!=null){
                shareItem.setFileHeader(fileHeader);
                shareItem.setUserFileShare(userFileShare);
                fileShareList.add(shareItem);
            }
        }
        return fileShareList;
    }

    @Override
    public ShareStateEnum shareFileWithFriend(int fromId, int toId, int fId, String remark) {
        UserFileShare userFileShare=new UserFileShare();
        userFileShare.setfId(fId);
        userFileShare.setFromId(fromId);
        userFileShare.setToId(toId);
        userFileShare.setRemark(remark);

        int insertCount = userFileShareDao.insert(userFileShare);
        if(insertCount==1){
            return ShareStateEnum.SUCCESS;
        }
        return ShareStateEnum.REPEAT;
    }

    @Override
    public DeleteStateEnum deleteByPrimaryKey(int fromId, int toId, int fId) {
        UserFileShare userFileShare=new UserFileShare();
        userFileShare.setfId(fId);
        userFileShare.setFromId(fromId);
        userFileShare.setToId(toId);

        int deleteCount = userFileShareDao.deleteByPrimaryKey(userFileShare);
        if(deleteCount==1){
            return DeleteStateEnum.SUCCESS;
        }else {
            return DeleteStateEnum.FAILED;
        }
    }
}
