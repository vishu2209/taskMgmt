package com.vishal.taskMgmt.sharedLib.user.dto;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserSearchDTO {
    Integer page;
    Integer size;
    String sortBy;
    String sortDir;
    String searchStr;
}